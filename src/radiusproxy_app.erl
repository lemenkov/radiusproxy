-module(radiusproxy_app).
-behaviour(application).
-export([start/2, stop/1]).

start(Type, StartArgs) ->
	{ok, {Ip, Port}} = application:get_env(radiusproxy, listen_address),
	supervisor:start_link({local, radiusproxy_sup}, radiusproxy_sup, [Ip, Port]).

stop(_State) ->
	ok.
