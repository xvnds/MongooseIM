-module(mongoose_c2s_socket).

-include_lib("public_key/include/public_key.hrl").
-include("mongoose_logger.hrl").

-export([new/4,
         handle_data/2,
         activate/1,
         close/1,
         is_channel_binding_supported/1,
         export_key_materials/5,
         get_peer_certificate/1,
         has_peer_cert/2,
         tcp_to_tls/2,
         is_ssl/1,
         send_xml/2]).

-export([get_ip/1,
         get_transport/1,
         get_conn_type/1]).

-callback new(term(), term(), mongoose_listener:options()) -> state().
-callback socket_peername(state()) -> {inet:ip_address(), inet:port_number()}.
-callback tcp_to_tls(state(), mongoose_listener:options()) ->
    {ok, state()} | {error, term()}.
-callback socket_handle_data(state(), {tcp | ssl, term(), iodata()}) ->
    iodata() | {raw, [exml:element()]} | {error, term()}.
-callback socket_activate(state()) -> ok.
-callback socket_close(state()) -> ok.
-callback socket_send_xml(state(), iodata() | exml_stream:element() | [exml_stream:element()]) ->
    ok | {error, term()}.
-callback get_peer_certificate(state()) -> peercert_return().
-callback has_peer_cert(state(), mongoose_listener:options()) -> boolean().
-callback is_channel_binding_supported(state()) -> boolean().
-callback export_key_materials(state(), Labels, Contexts, WantedLengths, ConsumeSecret) ->
    {ok, ExportKeyMaterials} |
    {error, atom() | exporter_master_secret_already_consumed | bad_input}
      when
      Labels :: [binary()],
      Contexts :: [binary() | no_context],
      WantedLengths :: [non_neg_integer()],
      ConsumeSecret :: boolean(),
      ExportKeyMaterials :: binary() | [binary()].
-callback is_ssl(state()) -> boolean().

-record(c2s_socket, {module :: module(),
                     state :: state()}).
-type socket() :: #c2s_socket{}.
-type state() :: term().
-type conn_type() :: c2s | c2s_tls.
-type peercert_return() :: no_peer_cert | {bad_cert, term()} | {ok, #'Certificate'{}}.
-export_type([socket/0, state/0, conn_type/0, peercert_return/0]).

-spec new(module(), ranch:ref(), mongoose_listener:transport_module(), mongoose_listener:options()) -> socket().
new(Module, Ref, Transport, LOpts) ->
    State = Module:new(Transport, Ref, LOpts),
    PeerIp = Module:socket_peername(State),
    verify_ip_is_not_blacklisted(PeerIp),
    Socket = #c2s_socket{
        module = Module,
        state = State},
    activate(Socket),
    Socket.

verify_ip_is_not_blacklisted(PeerIp) ->
    case mongoose_hooks:check_bl_c2s(PeerIp) of
        true ->
            ?LOG_INFO(#{what => c2s_blacklisted_ip, ip => PeerIp,
                        text => <<"Connection attempt from blacklisted IP">>}),
            throw({stop, {shutdown, ip_blacklisted}});
        false ->
            ok
    end.

-spec tcp_to_tls(socket(), mongoose_listener:options()) -> {ok, socket()} | {error, term()}.
tcp_to_tls(#c2s_socket{module = Module, state = State} = C2SSocket, LOpts) ->
    case Module:tcp_to_tls(State, LOpts) of
        {ok, NewState} ->
            {ok, C2SSocket#c2s_socket{state = NewState}};
        Error ->
            Error
    end.

-spec handle_data(socket(), {tcp | ssl, term(), iodata()}) ->
    iodata() | {raw, [term()]} | {error, term()}.
handle_data(#c2s_socket{module = Module, state = State}, Payload) ->
    Module:socket_handle_data(State, Payload);
handle_data(_, _) ->
    {error, bad_packet}.

-spec activate(socket()) -> ok | {error, term()}.
activate(#c2s_socket{module = Module, state = State}) ->
    Module:socket_activate(State).

-spec close(socket()) -> ok.
close(#c2s_socket{module = Module, state = State}) ->
    Module:socket_close(State).

-spec send_xml(socket(), exml_stream:element() | [exml_stream:element()]) -> ok | {error, term()}.
send_xml(#c2s_socket{module = Module, state = State}, XML) ->
    Module:socket_send_xml(State, XML).

-spec get_peer_certificate(socket()) -> peercert_return().
get_peer_certificate(#c2s_socket{module = Module, state = State}) ->
    Module:get_peer_certificate(State).

-spec has_peer_cert(socket(), mongoose_listener:options()) -> boolean().
has_peer_cert(#c2s_socket{module = Module, state = State}, LOpts) ->
    Module:has_peer_cert(State, LOpts).

-spec is_channel_binding_supported(socket()) -> boolean().
is_channel_binding_supported(#c2s_socket{module = Module, state = State}) ->
    Module:is_channel_binding_supported(State).

-spec is_ssl(socket()) -> boolean().
is_ssl(#c2s_socket{module = Module, state = State}) ->
    Module:is_ssl(State).

-spec get_transport(socket()) -> module().
get_transport(#c2s_socket{module = Module}) ->
    Module.

-spec export_key_materials(state(), Labels, Contexts, WantedLengths, ConsumeSecret) ->
    {ok, ExportKeyMaterials} |
    {error, undefined_tls_material | exporter_master_secret_already_consumed | bad_input}
      when
      Labels :: [binary()],
      Contexts :: [binary() | no_context],
      WantedLengths :: [non_neg_integer()],
      ConsumeSecret :: boolean(),
      ExportKeyMaterials :: binary() | [binary()].
export_key_materials(#c2s_socket{module = Module, state = State},
                     Labels, Contexts, WantedLengths, ConsumeSecret) ->
    Module:export_key_materials(State, Labels, Contexts, WantedLengths, ConsumeSecret).

-spec get_conn_type(socket()) -> conn_type().
get_conn_type(Socket) ->
    case is_ssl(Socket) of
        true -> c2s_tls;
        false -> c2s
    end.

-spec get_ip(socket()) -> term().
get_ip(#c2s_socket{module = Module, state = State}) ->
    Module:socket_peername(State).
