-module(fast_SUITE).

-compile([export_all, nowarn_export_all]).

-include_lib("stdlib/include/assert.hrl").
-include_lib("exml/include/exml.hrl").
-include_lib("escalus/include/escalus.hrl").
-include_lib("escalus/include/escalus_xmlns.hrl").

-define(FAST_MECH, <<"HT-SHA-256-NONE">>).
-define(NS_FAST, <<"urn:xmpp:fast:0">>).
-define(NS_SASL_2, <<"urn:xmpp:sasl:2">>).
-define(NS_BIND_2, <<"urn:xmpp:bind:0">>).

%%--------------------------------------------------------------------
%% Suite configuration
%%--------------------------------------------------------------------

all() ->
    [
     {group, basic}
    ].

groups() ->
    [
     {basic, [parallel],
      [
       server_announces_feature,
       authenticate_and_request_token,
       reauthenticate_with_obtained_token,
       reauth_fails_if_wrong_count,
       reauth_rotates_token
      ]}
    ].

%%--------------------------------------------------------------------
%% Init & teardown
%%--------------------------------------------------------------------

init_per_suite(Config) ->
    Config1 = load_modules(Config),
    escalus:init_per_suite(Config1).

end_per_suite(Config) ->
    escalus_fresh:clean(),
    dynamic_modules:restore_modules(Config),
    escalus:end_per_suite(Config).

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, Config) ->
    Config.

init_per_testcase(Name, Config) ->
    escalus:init_per_testcase(Name, Config).

end_per_testcase(Name, Config) ->
    escalus:end_per_testcase(Name, Config).

load_modules(Config) ->
    HostType = domain_helper:host_type(),
    Config1 = dynamic_modules:save_modules(HostType, Config),
    sasl2_helper:load_all_sasl2_modules(HostType),
    Config1.

%%--------------------------------------------------------------------
%% tests
%%--------------------------------------------------------------------

server_announces_feature(Config) ->
    Steps = [create_connect_tls, start_stream_get_features],
    #{features := Features} = sasl2_helper:apply_steps(Steps, Config),
    Feature = exml_query:path(Features, [{element_with_ns, <<"authentication">>, ?NS_SASL_2},
                                         {element, <<"inline">>},
                                         {element_with_ns, <<"fast">>, ?NS_FAST}]),
    ?assertNotEqual(undefined, Feature),
    Mechanisms = exml_query:paths(Feature, [{element, <<"mechanism">>}]),
    ?assertNotEqual([], Mechanisms).

authenticate_and_request_token(Config) ->
    Steps = [start_new_user,
             {?MODULE, auth_and_bind_request_token},
             receive_features, has_no_more_stanzas],
    #{tokens := [Token]} = sasl2_helper:apply_steps(Steps, Config),
    #{el_token := ElToken, bin_token := BinToken, expiry := Expiry} = Token,
    ?assertNotEqual(undefined, ElToken),
    ?assertNotEqual(undefined, Expiry),
    ?assertNotEqual(undefined, BinToken).

reauthenticate_with_obtained_token(Config) ->
    Steps = [start_new_user,
             {?MODULE, auth_and_bind_request_token},
             receive_features, has_no_more_stanzas, disconnect,
             connect_tls, start_stream_get_features,
             {?MODULE, reconnect_with_latest_token},
             receive_features, has_no_more_stanzas],
    #{answer := Response} = sasl2_helper:apply_steps(Steps, Config),
    Success = exml_query:path(Response, [{element_with_ns, <<"bound">>, ?NS_BIND_2}]),
    ?assertNotEqual(undefined, Success).

reauth_fails_if_wrong_count(Config) ->
    Steps = [start_new_user,
             {?MODULE, auth_and_bind_request_token},
             receive_features, has_no_more_stanzas, disconnect,
             connect_tls, start_stream_get_features,
             {?MODULE, reconnect_with_token_bad_count}],
    #{answer := Response} = sasl2_helper:apply_steps(Steps, Config),
    escalus:assert(is_stream_error, [<<"policy-violation">>, <<>>], Response).

reauth_rotates_token(Config) ->
    Steps = [start_new_user,
             {?MODULE, auth_and_bind_request_token},
             receive_features, has_no_more_stanzas, disconnect,
             connect_tls, start_stream_get_features,
             {?MODULE, reconnect_with_latest_token},
             receive_features, has_no_more_stanzas],
    #{answer := Response} = sasl2_helper:apply_steps(Steps, Config),
    Success = exml_query:path(Response, [{element_with_ns, <<"bound">>, ?NS_BIND_2}]),
    ?assertNotEqual(undefined, Success).




reconnect_with_latest_token(Config, Client, #{tokens := Tokens} = Data) ->
    [#{bin_token := BinToken, count := Count} | _ ] = Tokens,
    MarkToken = mark_auth_with_token(Count),
    {Client1, Data1} = sasl2_helper:session_establish(
                         Config, Client, Data, BinToken, ?FAST_MECH, [], [MarkToken]),
    {Client1, Data1#{count := Count + 1}}.

reconnect_with_token_bad_count(Config, Client, #{tokens := Tokens} = Data) ->
    [#{bin_token := BinToken} | _ ] = Tokens,
    MarkToken = mark_auth_with_token(0),
    sasl2_helper:session_establish(Config, Client, Data, BinToken, ?FAST_MECH, [], [MarkToken]).

auth_and_bind_request_token(Config, Client, Data) ->
    RequestToken = request_token(),
    {Client1, Data1} = sasl2_helper:plain_auth_bind(Config, Client, Data, [], [RequestToken]),
    Response = maps:get(answer, Data1),
    {Client1, maybe_add_token(Data, Response)}.

maybe_add_token(Data, Response) ->
    case exml_query:path(Response, [{element_with_ns, <<"token">>, ?NS_FAST}]) of
        undefined -> Data;
        Token ->
            Expiry = exml_query:attr(Token, <<"expiry">>),
            BinToken = exml_query:attr(Token, <<"token">>),
            OtherTokenStructs = maps:get(tokens, Data, []),
            TokenStruct = #{el_token => Token, bin_token => BinToken, expiry => Expiry, count => 1},
            Data#{tokens => [TokenStruct | OtherTokenStructs]}
    end.

mark_auth_with_token(Count) ->
    #xmlel{name = <<"fast">>,
           attrs = [{<<"xmlns">>, ?NS_FAST}, {<<"count">>, integer_to_binary(Count)}]}.

request_token() ->
    #xmlel{name = <<"request-token">>,
           attrs = [{<<"xmlns">>, ?NS_FAST}, {<<"mechanism">>, ?FAST_MECH}]}.










auth_and_bind_to_random_resource(Config) ->
    Steps = [start_new_user, {?MODULE, auth_and_bind}, receive_features, has_no_more_stanzas],
    #{answer := Success} = sasl2_helper:apply_steps(Steps, Config),
    ?assertMatch(#xmlel{name = <<"success">>, attrs = [{<<"xmlns">>, ?NS_SASL_2}]}, Success),
    Bound = exml_query:path(Success, [{element_with_ns, <<"bound">>, ?NS_BIND_2}]),
    ?assertNotEqual(undefined, Bound),
    Identifier = exml_query:path(Success, [{element, <<"authorization-identifier">>}, cdata]),
    #jid{resource = LResource} = jid:from_binary(Identifier),
    ?assert(0 =< byte_size(LResource), LResource).

auth_and_bind_do_not_expose_user_agent_id_in_client(Config) ->
    Steps = [start_new_user, {?MODULE, auth_and_bind_with_user_agent_uuid}, receive_features, has_no_more_stanzas],
    #{answer := Success, uuid := Uuid} = sasl2_helper:apply_steps(Steps, Config),
    ?assertMatch(#xmlel{name = <<"success">>, attrs = [{<<"xmlns">>, ?NS_SASL_2}]}, Success),
    Bound = exml_query:path(Success, [{element_with_ns, <<"bound">>, ?NS_BIND_2}]),
    ?assertNotEqual(undefined, Bound),
    Identifier = exml_query:path(Success, [{element, <<"authorization-identifier">>}, cdata]),
    #jid{resource = LResource} = jid:from_binary(Identifier),
    ?assertNotEqual(Uuid, LResource).

auth_and_bind_contains_client_tag(Config) ->
    Steps = [start_new_user, {?MODULE, auth_and_bind_with_tag}, receive_features, has_no_more_stanzas],
    #{answer := Success, tag := Tag} = sasl2_helper:apply_steps(Steps, Config),
    ?assertMatch(#xmlel{name = <<"success">>, attrs = [{<<"xmlns">>, ?NS_SASL_2}]}, Success),
    Bound = exml_query:path(Success, [{element_with_ns, <<"bound">>, ?NS_BIND_2}]),
    ?assertNotEqual(undefined, Bound),
    Identifier = exml_query:path(Success, [{element, <<"authorization-identifier">>}, cdata]),
    #jid{resource = LResource} = jid:from_binary(Identifier),
    ResourceParts = binary:split(LResource, <<"/">>, [global]),
    ?assertMatch([Tag, _], ResourceParts).

carbons_are_enabled_with_bind_inline_request(Config) ->
    Steps = [start_new_user, start_peer,
             {?MODULE, auth_and_bind_with_carbon_copies}, receive_features,
             {?MODULE, receive_message_carbon_arrives}, has_no_more_stanzas],
    sasl2_helper:apply_steps(Steps, Config).

csi_is_active_with_bind_inline_request(Config) ->
    Steps = [start_new_user, start_peer,
             {?MODULE, auth_and_bind_with_csi_active}, receive_features,
             {?MODULE, inactive_csi_msg_wont_arrive}, has_no_more_stanzas],
    sasl2_helper:apply_steps(Steps, Config).

csi_is_inactive_with_bind_inline_request(Config) ->
    Steps = [start_new_user, start_peer,
             {?MODULE, auth_and_bind_with_csi_inactive}, has_no_more_stanzas,
             {?MODULE, inactive_csi_msgs_do_not_arrive},
             {?MODULE, activate_csi}, receive_features,
             {?MODULE, receive_csi_msgs}, has_no_more_stanzas],
    sasl2_helper:apply_steps(Steps, Config).

stream_resumption_enable_sm_on_bind(Config) ->
    Steps = [start_new_user, start_peer,
             {?MODULE, auth_and_bind_with_sm_enabled},
             receive_features, has_no_more_stanzas],
    #{answer := Success} = sasl2_helper:apply_steps(Steps, Config),
    ?assertMatch(#xmlel{name = <<"success">>, attrs = [{<<"xmlns">>, ?NS_SASL_2}]}, Success),
    Enabled = exml_query:path(Success, [{element_with_ns, <<"bound">>, ?NS_BIND_2},
                                        {element_with_ns, <<"enabled">>, ?NS_STREAM_MGNT_3}]),
    ?assertNotEqual(undefined, Enabled).

stream_resumption_enable_sm_on_bind_with_resume(Config) ->
    Steps = [start_new_user, start_peer,
             {?MODULE, auth_and_bind_with_sm_resume_enabled},
             receive_features, has_no_more_stanzas],
    #{answer := Success} = sasl2_helper:apply_steps(Steps, Config),
    ?assertMatch(#xmlel{name = <<"success">>, attrs = [{<<"xmlns">>, ?NS_SASL_2}]}, Success),
    Enabled = exml_query:path(Success, [{element_with_ns, <<"bound">>, ?NS_BIND_2},
                                        {element_with_ns, <<"enabled">>, ?NS_STREAM_MGNT_3}]),
    ?assertNotEqual(undefined, Enabled).

stream_resumption_failing_does_bind_and_contains_sm_status(Config) ->
    Steps = [create_user, buffer_messages_and_die, connect_tls, start_stream_get_features,
             {?MODULE, auth_and_bind_with_resumption_unknown_smid},
             receive_features, has_no_more_stanzas],
    #{answer := Success, tag := Tag} = sasl2_helper:apply_steps(Steps, Config),
    ?assertMatch(#xmlel{name = <<"success">>, attrs = [{<<"xmlns">>, ?NS_SASL_2}]}, Success),
    Bound = exml_query:path(Success, [{element_with_ns, <<"bound">>, ?NS_BIND_2}]),
    ?assertNotEqual(undefined, Bound),
    Resumed = exml_query:path(Success, [{element_with_ns, <<"failed">>, ?NS_STREAM_MGNT_3}]),
    escalus:assert(is_sm_failed, [<<"item-not-found">>], Resumed),
    Identifier = exml_query:path(Success, [{element, <<"authorization-identifier">>}, cdata]),
    #jid{resource = LResource} = jid:from_binary(Identifier),
    ResourceParts = binary:split(LResource, <<"/">>, [global]),
    ?assertMatch([Tag, _], ResourceParts).

stream_resumption_overrides_bind_request(Config) ->
    Steps = [create_user, buffer_messages_and_die, connect_tls, start_stream_get_features,
             {?MODULE, auth_and_bind_with_resumption}, has_no_more_stanzas],
    #{answer := Success, smid := SMID} = sasl2_helper:apply_steps(Steps, Config),
    ?assertMatch(#xmlel{name = <<"success">>, attrs = [{<<"xmlns">>, ?NS_SASL_2}]}, Success),
    Resumed = exml_query:path(Success, [{element_with_ns, <<"resumed">>, ?NS_STREAM_MGNT_3}]),
    ?assert(escalus_pred:is_sm_resumed(SMID, Resumed)).


%% Step helpers
