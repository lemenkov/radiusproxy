-module(radiusproxy).

-include_lib("eradius/include/eradius_lib.hrl").

-include_lib("eradius/include/dictionary.hrl").
-include_lib("eradius/include/dictionary_cisco.hrl").
-include_lib("eradius/include/dictionary_ipport.hrl").
-include_lib("eradius/include/dictionary_openser.hrl").
-include_lib("eradius/include/dictionary_rfc2865.hrl").
-include_lib("eradius/include/dictionary_rfc2866.hrl").
-include_lib("eradius/include/dictionary_rfc2869.hrl").

-behavior(gen_amp_server).

-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-export([start_link/2]).
-export(['SendAccounting'/2]).

-define(Type_Start, 1).
-define(Type_Stop, 2).

% radiusproxy:start_link({127,0,0,1}, 8889).
start_link(Ip, Port) ->
        gen_amp_sup:start_link(?MODULE, Ip, Port).

init(_) ->
	eradius_dict:start(),
	eradius_dict:load_tables([
			"dictionary",
			"dictionary_cisco",
			"dictionary_ipport",
			"dictionary_openser",
			"dictionary_rfc2865",
			"dictionary_rfc2866",
			"dictionary_rfc2869"
	]),
	eradius_acc:start(),
	T = ets:new(radacc,[public, named_table]),
	{ok, T}.

handle_call(_Request, _From, State) ->
	{reply, ok, State}.

handle_cast(_Request, State) ->
	{noreply, State}.

handle_info(_Info, State) ->
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

'SendAccounting'(Params, State) when is_list(Params) ->
	error_logger:warning_msg("Params: ~p~n", [Params]),

	CallId = binary_to_list(proplists:get_value(callid, Params)),
	CallLeg = binary_to_list(proplists:get_value(callleg, Params)),
	Type = type_to_int(proplists:get_value(type, Params)),

	ets:insert_new(radacc, {{{callid, CallId}, {calleg, CallLeg}, {type, Type}}, Params}),

	case Type of
		?Type_Start ->
			send_acct(Params);
		?Type_Stop ->
			case ets:lookup(radacc, {{callid, CallId}, {calleg, CallLeg}, {type, ?Type_Start}}) of
				[] ->
					% Don't send - enqueue only
					ok;
				_ ->
					send_acct(Params),
					ets:delete(radacc, {{callid, CallId}, {calleg, CallLeg}, {type, ?Type_Start}}),
					ets:delete(radacc, {{callid, CallId}, {calleg, CallLeg}, {type, ?Type_Stop}})
			end
	end,
	{noreply_and_close, State}.

send_acct(Params) ->
	Method = method_to_int(proplists:get_value(method, Params)),
	Caller = binary_to_list(proplists:get_value(caller, Params, <<"Anonymous">>)),
	Called = binary_to_list(proplists:get_value(called, Params)),
	CallId = binary_to_list(proplists:get_value(callid, Params)),
	CallLeg = binary_to_list(proplists:get_value(callleg, Params)),
	FromTag = binary_to_list(proplists:get_value(from_tag, Params)),
	ToTag = binary_to_list(proplists:get_value(to_tag, Params)),
	RelSource = binary_to_list(proplists:get_value(rs, Params)),
	{ok, SipAddr} = inet_parse:address(binary_to_list(proplists:get_value(sip_addr, Params))),
	SipCode = proplists:get_value(sip_code, Params),
	SipPort = list_to_integer(binary_to_list(proplists:get_value(sip_port, Params))),
	Source = binary_to_list(proplists:get_value(source, Params)),
	Type = type_to_int(proplists:get_value(type, Params)),

	Req = #rad_accreq{
			servers = [[{192,168,1,100},1813,"testpass"]],
			login_time = erlang:now(),
			std_attrs=[
				{?Acct_Session_Id, CallId},
				{?User_Name, Caller},
				{?Calling_Station_Id, Caller},
				{?Called_Station_Id, Called},
				{?Acct_Delay_Time, 0},
				{?Service_Type, 15}, % "Sip-Session"
				{?Sip_Method, Method},
				{?Sip_From_Tag, FromTag},
				{?Sip_To_Tag, ToTag},
				{?Sip_Branch_ID, CallLeg},
				{?Connect_Info, Source},
				{?NAS_IP_Address, SipAddr},
				{?NAS_Port, SipPort},
				{?Sip_Response_Code, list_to_integer(binary_to_list(SipCode))} % This violates /usr/share/freeradius/dictionary.sip
			],
			vend_attrs = case Type of
				?Type_Start ->
					[
						{?Cisco, [{?call_id, CallId ++ "_b2b_" ++ CallLeg}]},
						{?Cisco, [{?release_source, RelSource}]},
						{?Cisco, [{?h323_setup_time, date_time_fmt()}]}
					];
				?Type_Stop ->
					[
						{?Cisco, [{?call_id, CallId ++ "_b2b_" ++ CallLeg}]},
						{?Cisco, [{?release_source, RelSource}]},
						{?Cisco, [{?h323_disconnect_time, date_time_fmt()}]},
						{?Cisco, [{?h323_disconnect_cause, sip_reply_to_h323_err(SipCode)}]}
					]
			end
		},
	case Type of
		?Type_Start -> eradius_acc:acc_start(Req);
		?Type_Stop -> eradius_acc:acc_stop(Req)
	end,
	{reply_and_close, noreply}.

% According to /usr/share/freeradius/dictionary.openser
method_to_int (<<"Other">>) -> 0;
method_to_int (<<"Invite">>) -> 1;
method_to_int (<<"Cancel">>) -> 2;
method_to_int (<<"Ack">>) -> 4;
method_to_int (<<"Bye">>) -> 8.

% According to /usr/share/freeradius/dictionary.rfc2866
type_to_int(<<"Start">>) -> ?Type_Start;
type_to_int(<<"Stop">>) -> ?Type_Stop.

date_time_fmt() ->
        {{YYYY,MM,DD},{Hour,Min,Sec}} = erlang:localtime(),
        lists:flatten(io_lib:format("~4.4.0w-~2.2.0w-~2.2.0w ~2.2.0w:~2.2.0w:~2.2.0w", [YYYY, MM, DD, Hour,Min,Sec])).

% http://www.h2o.co.uk/isdnerr.htm
% http://www.quintum.com/support/xplatform/ivr_acct/webhelp/Disconnect_Cause_Codes.htm
% http://www.cisco.com/en/US/docs/ios/12_2t/12_2t11/feature/guide/ftmap.html

sip_reply_to_h323_err(400) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(401) -> "39"; %'Bearer capability not authorized'
sip_reply_to_h323_err(402) -> "15"; %'Call rejected'
sip_reply_to_h323_err(403) -> "39"; %'Bearer capability not authorized'
sip_reply_to_h323_err(404) -> "1"; % 'Unallocated number'
sip_reply_to_h323_err(405) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(406) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(407) -> "15"; %'Call rejected'
sip_reply_to_h323_err(408) -> "66"; %'Recover on Expires timeout'
sip_reply_to_h323_err(409) -> "29"; %'Temporary failure'
sip_reply_to_h323_err(410) -> "1"; % 'Unallocated number'
sip_reply_to_h323_err(411) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(413) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(414) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(415) -> "4f"; %'Service or option not implemented'
sip_reply_to_h323_err(420) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(480) -> "12"; %'No user response'
sip_reply_to_h323_err(481) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(482) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(483) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(484) -> "1c"; %'Address incomplete'
sip_reply_to_h323_err(485) -> "1"; % 'Unallocated number'
sip_reply_to_h323_err(486) -> "11"; %'User busy'
sip_reply_to_h323_err(487) -> "12"; %'No user responding'
sip_reply_to_h323_err(488) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(500) -> "29"; %'Temporary failure'
sip_reply_to_h323_err(501) -> "4f"; %'Service or option not implemented'
sip_reply_to_h323_err(502) -> "26"; %'Network out of order'
sip_reply_to_h323_err(503) -> "3f"; %'Service or option unavailable'
sip_reply_to_h323_err(504) -> "66"; %'Recover on Expires timeout'
sip_reply_to_h323_err(505) -> "7f"; %'Interworking, unspecified'
sip_reply_to_h323_err(580) -> "2f"; %'Resource unavailable, unspecified'
sip_reply_to_h323_err(600) -> "11"; %'User busy'
sip_reply_to_h323_err(603) -> "15"; %'Call rejected'
sip_reply_to_h323_err(604) -> "1"; % 'Unallocated number'
sip_reply_to_h323_err(606) -> "3a"; %'Bearer capability not presently available'
sip_reply_to_h323_err(SipCode) ->
	if
		SipCode >= 400 -> "7f";
		SipCode < 200 -> "10";
		true -> "0"
	end.

%% Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

test_gen() ->
	ok.

-endif.
