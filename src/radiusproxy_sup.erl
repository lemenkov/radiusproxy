-module(radiusproxy_sup).
-behaviour(supervisor).

-export([init/1]).

init(Args) ->
	Child = {radiusproxy,{radiusproxy,start_link,Args},permanent,2000,worker,[radiusproxy]},
	{ok,{{one_for_one,10,1}, [Child]}}.

