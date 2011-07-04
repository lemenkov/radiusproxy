-module(radiusproxy_app).
-behaviour(application).
-export([start/2, stop/1]).

start(_Type, StartArgs) ->
	supervisor:start_link({local, radiusproxy_sup}, ser_sup, StartArgs).

stop(_State) ->
	ok.
