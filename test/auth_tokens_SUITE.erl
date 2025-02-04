-module(auth_tokens_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("exml/include/exml.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-include("jlib.hrl").
-include("mod_auth_token.hrl").

-import(prop_helper, [prop/2]).

-define(TESTED, mod_auth_token).
-define(ae(Expected, Actual), ?assertEqual(Expected, Actual)).

-define(l2b(List), list_to_binary(List)).
-define(i2b(I), integer_to_binary(I)).

all() ->
    [{group, creation},
     {group, revocation}].

groups() ->
    [
     {creation, [],
      [
       expiry_date_roundtrip_test,
       join_and_split_with_base16_and_zeros_are_reversible_property,
       serialize_deserialize_property,
       validation_test,
       validation_property,
       validity_period_test,
       choose_key_by_token_type
      ]},
     {revocation, [],
      [
       revoked_token_is_not_valid
      ]}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(jid),
    mongoose_config:set_opts(opts()),
    async_helper:start(Config, [{mongoose_instrument, start_link, []},
                                {mongooseim_helper, start_link_loaded_hooks, []}]).

end_per_suite(Config) ->
    async_helper:stop_all(Config),
    mongoose_config:erase_opts().

opts() ->
    #{{modules, host_type()} => #{?TESTED => config_parser_helper:default_mod_config(?TESTED)},
      instrumentation => config_parser_helper:default_config([instrumentation])}.

init_per_testcase(Test, Config)
        when Test =:= serialize_deserialize_property;
             Test =:= validation_test;
             Test =:= validation_property;
             Test =:= choose_key_by_token_type ->
    mock_keystore(),
    mock_rdbms_backend(),
    Config;
init_per_testcase(validity_period_test, Config) ->
    mock_rdbms_backend(),
    mock_gen_iq_handler(),
    Config;
init_per_testcase(revoked_token_is_not_valid, Config) ->
    mock_tested_backend(),
    mock_keystore(),
    Config;
init_per_testcase(_, C) -> C.

end_per_testcase(Test, _C)
        when Test =:= serialize_deserialize_property;
             Test =:= validation_test;
             Test =:= validation_property;
             Test =:= choose_key_by_token_type ->
    meck:unload(mod_auth_token_backend);
end_per_testcase(validity_period_test, _C) ->
    meck:unload(mod_auth_token_backend),
    meck:unload(gen_iq_handler);
end_per_testcase(revoked_token_is_not_valid, _C) ->
    meck:unload(mod_auth_token_backend);
end_per_testcase(_, _) ->
    ok.

%%
%% Tests
%%

expiry_date_roundtrip_test(_) ->
    D = {{2015,9,17},{20,28,21}}, %% DateTime
    S =  mod_auth_token:datetime_to_seconds(D),
    ResD = mod_auth_token:seconds_to_datetime(S),
    ?ae(D, ResD).

join_and_split_with_base16_and_zeros_are_reversible_property(_) ->
    prop(join_and_split_are_reversible_property,
         ?FORALL(RawToken, serialized_token(<<0>>),
                 is_join_and_split_with_base16_and_zeros_reversible(RawToken))).

serialize_deserialize_property(_) ->
    prop(serialize_deserialize_property,
         ?FORALL(Token, token(), is_serialization_reversible(Token))).

validation_test(Config) ->
    validation_test(Config, provision_token_example()),
    validation_test(Config, refresh_token_example()).

validation_test(_, ExampleToken) ->
    %% given
    Serialized = ?TESTED:serialize(ExampleToken),
    ct:pal("ExampleToken:~n  ~p", [ExampleToken]),
    %% note that mod_auth_token:deserialize/1 recomputes token_body.
    %% therefore the supplied MAC signature (which is part of the serialized data)
    %% may become invalid if the vcard xml binary data changes after running
    %% exml:parse/1 and exml:to_binary/1 on it.
    DeserialisedToken = ?TESTED:deserialize(Serialized),
    ct:pal("DeserialisedToken:~n  ~p", [DeserialisedToken]),
    TokenWithMac = ?TESTED:token_with_mac(host_type(),
                                          DeserialisedToken#token{
                                            mac_signature = undefined,
                                            token_body = undefined}),
    ct:pal("TokenWithMac:~n  ~p", [TokenWithMac]),
    %% when
    Result = ?TESTED:authenticate(host_type(), Serialized),
    ct:pal("Result: ~p", [Result]),

    %% then
    ?ae(true, is_validation_success(Result)).

validation_property(_) ->
    prop(validation_property,
         ?FORALL(Token, valid_token(), is_valid_token_prop(Token))).

validity_period_test(_) ->
    %% given
    ok = ?TESTED:start(host_type(), mongoose_config:get_opt([{modules, host_type()}, ?TESTED])),
    UTCSeconds = utc_now_as_seconds(),
    ExpectedSeconds = UTCSeconds + 3600, %% seconds per hour
    %% when
    ActualDT = ?TESTED:expiry_datetime(host_type(), access, UTCSeconds),
    %% then
    ?ae(calendar:gregorian_seconds_to_datetime(ExpectedSeconds), ActualDT).

choose_key_by_token_type(_) ->
    %% given mocked keystore (see init_per_testcase)
    %% when mod_auth_token asks for key for given token type
    %% then the correct key is returned
    ?ae(<<"access_or_refresh">>, ?TESTED:get_key_for_host_type(host_type(), access)),
    ?ae(<<"access_or_refresh">>, ?TESTED:get_key_for_host_type(host_type(), refresh)),
    ?ae(<<"provision">>, ?TESTED:get_key_for_host_type(host_type(), provision)).

is_join_and_split_with_base16_and_zeros_reversible(RawToken) ->
    MAC = binary:encode_hex(crypto:mac(hmac, sha384, <<"unused_key">>, RawToken), lowercase),
    Token = <<RawToken/bytes, 0, MAC/bytes>>,
    BodyPartsLen = length(binary:split(RawToken, <<0>>, [global])),
    Parts = binary:split(Token, <<0>>, [global]),
    case BodyPartsLen + 1 == length(Parts) of
        true -> true;
        false ->
            ct:pal("invalid MAC: ~s", [MAC]),
            false
    end.

is_serialization_reversible(Token) ->
    Token =:= ?TESTED:deserialize(?TESTED:serialize(Token)).

is_valid_token_prop(Token) ->
    Serialized = ?TESTED:serialize(Token),
    R = ?TESTED:authenticate(host_type(), Serialized),
    case is_validation_success(R) of
        true -> true;
        _    -> ct:fail(R)
    end.

is_validation_success(Result) ->
    case Result of
        {ok, _, _} -> true;
        {ok, _, _, _} -> true;
        _ -> false
    end.

revoked_token_is_not_valid(_) ->
    %% given
    ValidSeqNo = 123456,
    RevokedSeqNo = 123455,
    self() ! {valid_seq_no, ValidSeqNo},
    T = #token{type = refresh,
               expiry_datetime = ?TESTED:seconds_to_datetime(utc_now_as_seconds() + 10),
               user_jid = jid:from_binary(<<"alice@localhost">>),
               sequence_no = RevokedSeqNo},
    Revoked = ?TESTED:serialize(?TESTED:token_with_mac(host_type(), T)),
    %% when
    ValidationResult = ?TESTED:authenticate(host_type(), Revoked),
    %% then
    {error, _} = ValidationResult.

%%
%% Helpers
%%

datetime_to_seconds(DateTime) ->
    calendar:datetime_to_gregorian_seconds(DateTime).

seconds_to_datetime(Seconds) ->
    calendar:gregorian_seconds_to_datetime(Seconds).

utc_now_as_seconds() ->
    calendar:datetime_to_gregorian_seconds(calendar:universal_time()).

%% This is a negative test case helper - that's why we invert the logic below.
%% I.e. we expect the property to fail.
negative_prop(Name, Prop) ->
    Props = proper:conjunction([{Name, Prop}]),
    [[{Name, _}]] = proper:quickcheck(Props, [verbose, long_result, {numtests, 50}]).

mock_rdbms_backend() ->
    meck:new(mod_auth_token_backend, []),
    meck:expect(mod_auth_token_backend, start, fun(_, _) -> ok end),
    meck:expect(mod_auth_token_backend, get_valid_sequence_number,
                fun (_, _) -> valid_seq_no_threshold() end),
    ok.

mock_keystore() ->
    gen_hook:add_handler(get_key, host_type(), fun ?MODULE:mod_keystore_get_key/3, #{}, 50).

mock_gen_iq_handler() ->
    meck:new(gen_iq_handler, []),
    meck:expect(gen_iq_handler, add_iq_handler_for_domain, fun (_, _, _, _, _, _) -> ok end).

mod_keystore_get_key(_, #{key_id := {KeyName, _} = KeyID}, _) ->
    Acc = case KeyName of
        token_secret -> [{KeyID, <<"access_or_refresh">>}];
        provision_pre_shared -> [{KeyID, <<"provision">>}]
    end,
    {ok, Acc}.

mock_tested_backend() ->
    meck:new(mod_auth_token_backend, []),
    meck:expect(mod_auth_token_backend, get_valid_sequence_number,
                fun (_, _) ->
                        receive {valid_seq_no, SeqNo} -> SeqNo end
                end).

provision_token_example() ->
    #token{
        type = provision,
        expiry_datetime = {{2055,10,27},{10,54,22}},
        user_jid = jid:make(<<"cee2m1s0i">>,domain(),<<>>),
        sequence_no = undefined,
        vcard = #xmlel{
            name = <<"vCard">>,
            attrs = #{<<"sgzldnl">> => <<"inxdutpu">>,
                      <<"scmgsrfi">> => <<"nhgybwu">>,
                      <<"ixrsmzee">> => <<"rysdh">>,
                      <<"oxwothgyei">> => <<"wderkfgexv">>},
            children = [
                #xmlel{
                    name = <<"nqe">>,
                    attrs = #{<<"i">> => <<"u">>,
                              <<"gagnixjgml">> => <<"odaorofnra">>,
                              <<"ijz">> => <<"zvbrqnybi">>},
                    children = [
                        #xmlcdata{content = <<"uprmzqf">>},
                        #xmlel{name = <<"lnnitxm">>,
                               attrs = #{<<"qytehi">> => <<"axl">>,
                                         <<"xaxforb">> => <<"jrdeydsqhj">>}},
                        #xmlcdata{content = <<"pncgsaxl">>},
                        #xmlel{name = <<"jfofazuau">>,
                               attrs = #{<<"si">> => <<"l">>}}
                    ]},
                #xmlel{name = <<"moy">>,
                       attrs = #{<<"femjc">> => <<"qqb">>,
                                 <<"tirfmekvpk">> => <<"sa">>}},
                #xmlcdata{content = <<"bgxlyqdeeuo">>}
            ]},
        mac_signature = <<96,213,61,178,182,8,167,202,120,67,82,228,108,171,74,98,88,236,
                          200,77,44,151,199,213,43,193,109,139,197,14,179,107,72,243,50,
                          199,208,14,254,218,47,164,249,1,212,167,90,218>>,
        token_body = <<112,114,111,118,105,115,105,111,110,0,99,101,101,50,109,49,
                       115,48,105,64,108,111,99,97,108,104,111,115,116,0,54,52,56,
                       55,53,52,54,54,52,54,50,0,60,118,67,97,114,100,32,105,120,
                       114,115,109,122,101,101,61,39,114,121,115,100,104,39,32,111,
                       120,119,111,116,104,103,121,101,105,61,39,119,100,101,114,
                       107,102,103,101,120,118,39,32,115,99,109,103,115,114,102,105,
                       61,39,110,104,103,121,98,119,117,39,32,115,103,122,108,100,
                       110,108,61,39,105,110,120,100,117,116,112,117,39,62,60,110,
                       113,101,32,103,97,103,110,105,120,106,103,109,108,61,39,111,
                       100,97,111,114,111,102,110,114,97,39,32,105,61,39,117,39,32,
                       105,106,122,61,39,122,118,98,114,113,110,121,98,105,39,62,
                       117,112,114,109,122,113,102,60,108,110,110,105,116,120,109,
                       32,113,121,116,101,104,105,61,39,97,120,108,39,32,120,97,120,
                       102,111,114,98,61,39,106,114,100,101,121,100,115,113,104,106,
                       39,47,62,112,110,99,103,115,97,120,108,60,106,102,111,102,97,
                       122,117,97,117,32,115,105,61,39,108,39,47,62,60,47,110,113,
                       101,62,60,109,111,121,32,102,101,109,106,99,61,39,113,113,98,
                       39,32,116,105,114,102,109,101,107,118,112,107,61,39,115,97,
                       39,47,62,98,103,120,108,121,113,100,101,101,117,111,60,47,
                       118,67,97,114,100,62>>}.

refresh_token_example() ->
    #token{
        type = refresh,
        expiry_datetime = {{2055,10,27},{10,54,14}},
        user_jid = jid:make(<<"a">>,domain(),<<>>),
        sequence_no = 4,
        vcard = undefined,
        mac_signature = <<151,225,117,181,0,168,228,208,238,182,157,253,24,200,231,25,189,
                          160,176,144,85,193,20,108,31,23,46,35,215,41,250,57,68,201,45,33,
                          241,219,197,83,155,118,217,92,172,42,8,118>>,
       token_body = <<114,101,102,114,101,115,104,0,97,64,108,111,99,97,108,104,111,115,
                      116,0,54,52,56,55,53,52,54,54,52,53,52,0,52>>}.

%%
%% Generators
%%

valid_token() ->
    ?LET(TokenParts, {token_type(), valid_expiry_datetime(),
                      bare_jid(), valid_seq_no(), vcard()},
         make_token(TokenParts)).

%% Arbitrary date in the future.
validity_threshold() ->
    {{2055,10,27}, {10,54,14}}.

valid_seq_no_threshold() ->
    3.

valid_seq_no() ->
    integer(valid_seq_no_threshold() + 1, inf).

token() ->
    ?LET(TokenParts, {token_type(), expiry_datetime(),
                      bare_jid(), seq_no(), vcard()},
         make_token(TokenParts)).

make_token({Type, Expiry, JID, SeqNo, VCard}) ->
    T = #token{type = Type,
               expiry_datetime = Expiry,
               user_jid = jid:from_binary(JID)},
    case Type of
        access ->
            ?TESTED:token_with_mac(host_type(), T);
        refresh ->
            ?TESTED:token_with_mac(host_type(), T#token{sequence_no = SeqNo});
        provision ->
            ?TESTED:token_with_mac(host_type(), T#token{vcard = VCard})
    end.

serialized_token(Sep) ->
    ?LET({Type, JID, Expiry, SeqNo},
         {oneof([<<"access">>, <<"refresh">>]), bare_jid(), expiry_date_as_seconds(), seq_no()},
         case Type of
             <<"access">> ->
                 <<"access", Sep/bytes, JID/bytes, Sep/bytes, (?i2b(Expiry))/bytes>>;
             <<"refresh">> ->
                 <<"refresh", Sep/bytes, JID/bytes, Sep/bytes, (?i2b(Expiry))/bytes,
                   Sep/bytes, (?i2b(SeqNo))/bytes>>
         end).

token_type() ->
    oneof([access, refresh, provision]).

expiry_datetime() ->
    ?LET(Seconds, pos_integer(), seconds_to_datetime(Seconds)).

valid_expiry_datetime() ->
    ?LET(Seconds, integer( datetime_to_seconds(validity_threshold()),
                           datetime_to_seconds({{2100,1,1},{0,0,0}}) ),
         seconds_to_datetime(Seconds)).

expiry_date_as_seconds() -> pos_integer().

seq_no() -> pos_integer().

vcard() ->
    ?LET(Element, xmlel_gen:xmlel(3),
         Element#xmlel{name = <<"vCard">>}).

bare_jid() ->
    ?LET({Username, Domain}, {username(), domain()},
         <<(?l2b(Username))/bytes, "@", (Domain)/bytes>>).

%full_jid() ->
%    ?LET({Username, Domain, Res}, {username(), domain(), resource()},
%         <<(?l2b(Username))/bytes, "@", (?l2b(Domain))/bytes, "/", (?l2b(Res))/bytes>>).

username() -> ascii_string().
domain()   -> <<"localhost">>.
%resource() -> ascii_string().
host_type()   -> <<"localhost">>.

ascii_string() ->
    ?LET({Alpha, Alnum}, {ascii_alpha(), list(ascii_alnum())}, [Alpha | Alnum]).

ascii_digit() -> choose($0, $9).
ascii_lower() -> choose($a, $z).
ascii_upper() -> choose($A, $Z).
ascii_alpha() -> union([ascii_lower(), ascii_upper()]).
ascii_alnum() -> union([ascii_alpha(), ascii_digit()]).
