%% TODO implement channel-bindings, do together with regular sasl in the future
-module(mod_fast).
% -xep([{xep, fast}, {version, "0.0.1"}, {status, partial}]).

-include("jlib.hrl").
-include("mongoose_config_spec.hrl").

-behaviour(gen_mod).

-record(token, {
          mechanism :: crypto:hash_algorithm(),
          secret :: binary(),
          issued_at :: integer(),
          expires_at :: integer()
        }).
-type token() :: #token{}.

%% gen_mod callbacks
-export([start/2, stop/1, deps/2, config_spec/0, hooks/1, supported_features/0]).
-export([hash_to_bin/1, validity_to_milliseconds/1]).

-export([
         sasl2_stream_features/3,
         sasl2_start/3,
         sasl2_success/3,
         sasl2_auth/3
        ]).

%% gen_mod
-spec start(mongooseim:host_type(), gen_mod:module_opts()) -> ok.
start(_HostType, _Opts) ->
    ok.

-spec stop(mongooseim:host_type()) -> ok.
stop(_HostType) ->
    ok.

-spec deps(mongooseim:host_type(), gen_mod:module_opts()) -> gen_mod_deps:deps().
deps(_HostType, Opts) ->
    [{mod_sasl2, Opts, hard}].

-spec config_spec() -> mongoose_config_spec:config_section().
config_spec() ->
    #section{
       items = #{<<"hash">> => hash_spec(),
                 <<"entropy">> => #option{type = integer, validate = positive},
                 <<"max_count">> => #option{type = integer, validate = positive},
                 <<"validity_period">> => validity_period_spec()},
       defaults = #{<<"hash">> => hash_names(),
                    <<"max_count">> => 256,
                    <<"entropy">> => 16, %% 16 bytes, so 128 bits
                    <<"validity_period">> => 7 * timer:hours(24)} %% 5 days
      }.

-spec validity_period_spec() -> mongoose_config_spec:config_section().
validity_period_spec() ->
    #section{
       items = #{<<"value">> => #option{type = integer, validate = non_negative},
                 <<"unit">> => #option{type = atom, validate = {enum, [days, hours, minutes, seconds]}}},
       process = fun ?MODULE:validity_to_milliseconds/1,
       required = all
      }.

-spec hash_spec() -> mongoose_config_spec:config_list().
hash_spec() ->
    #list{items = #option{type = atom, validate = {enum, hash_atoms()},
                          process = fun ?MODULE:hash_to_bin/1},
          validate = unique_non_empty}.

-spec hooks(mongooseim:host_type()) -> gen_hook:hook_list().
hooks(HostType) ->
    [
     {sasl2_stream_features, HostType, fun ?MODULE:sasl2_stream_features/3, #{}, 50},
     {sasl2_start, HostType, fun ?MODULE:sasl2_start/3, #{}, 50},
     {sasl2_success, HostType, fun ?MODULE:sasl2_success/3, #{}, 50}, %% after SM
     {sasl2_auth, HostType, fun ?MODULE:sasl2_auth/3, #{mechs => hash_names()}, 50}
    ].

-spec supported_features() -> [atom()].
supported_features() ->
    [dynamic_domains].

%% Hook handlers
-spec sasl2_stream_features(Acc, #{c2s_data := mongoose_c2s:data()}, gen_hook:extra()) ->
    {ok, Acc} when Acc :: [exml:element()].
sasl2_stream_features(Acc, _, #{host_type := HostType}) ->
    Feature = feature(HostType),
    {ok, lists:keystore(feature_name(), #xmlel.name, Acc, Feature)}.

-spec sasl2_start(SaslAcc, #{stanza := exml:element()}, gen_hook:extra()) ->
    {ok, SaslAcc} when SaslAcc :: mongoose_acc:t().
sasl2_start(SaslAcc, #{stanza := El}, _) ->
    case exml_query:path(El, [{element_with_ns, <<"request-token">>, ?NS_FAST}]) of
        undefined ->
            {ok, SaslAcc};
        Request ->
            {ok, mod_sasl2:put_inline_request(SaslAcc, ?MODULE, Request)}
    end.

-spec sasl2_success(SaslAcc, mod_sasl2:c2s_state_data(), gen_hook:extra()) ->
    {ok, SaslAcc} when SaslAcc :: mongoose_acc:t().
sasl2_success(SaslAcc, _, #{host_type := HostType}) ->
    case mod_sasl2:get_inline_request(SaslAcc, ?MODULE, undefined) of
        undefined ->
            {ok, SaslAcc};
        #{request := Req, status := pending} ->
            Mech = get_mech(Req),
            maybe_return_token(SaslAcc, HostType, Mech)
    end.

-spec sasl2_auth(SaslAcc, map(), gen_hook:extra()) ->
    {ok, SaslAcc} when SaslAcc :: mongoose_acc:t().
sasl2_auth(SaslAcc, #{mech := Mech}, #{mechs := Mechs, host_type := _HostType}) ->
    case lists:member(Mech, Mechs) of
        true ->
            {stop, SaslAcc};
        false ->
            {ok, SaslAcc}
    end.

maybe_return_token(SaslAcc, _, invalid_mech) ->
    {ok, SaslAcc};
maybe_return_token(SaslAcc, HostType, Mech) ->
    Token = generate_token(HostType, Mech),
    TokenEl = token_el(Token),
    SaslAcc1 = mod_sasl2:update_inline_request(SaslAcc, ?MODULE, TokenEl, success),
    {ok, SaslAcc1}.

-spec get_mech(exml:element()) -> crypto:hash_algorithm().
get_mech(Req) ->
    case exml_query:attr(Req, <<"mechanism">>) of
        <<"HT-SHA-NONE">> -> sha;
        <<"HT-SHA-224-NONE">> -> sha224;
        <<"HT-SHA-256-NONE">> -> sha256;
        <<"HT-SHA-384-NONE">> -> sha384;
        <<"HT-SHA-512-NONE">> -> sha512;
        <<"HT-SHA3-224-NONE">> -> sha3_224;
        <<"HT-SHA3-256-NONE">> -> sha3_256;
        <<"HT-SHA3-384-NONE">> -> sha3_384;
        <<"HT-SHA3-512-NONE">> -> sha3_512;
        _ -> invalid_mech
    end.

-spec generate_token(mongooseim:host_type(), crypto:hash_algorithm()) -> token().
generate_token(HostType, Mech) ->
    Now = erlang:system_time(millisecond),
    ValidityMs = gen_mod:get_module_opt(HostType, ?MODULE, validity_period),
    KeySize = gen_mod:get_module_opt(HostType, ?MODULE, entropy),
    Secret = crypto:strong_rand_bytes(KeySize),
    #token{mechanism = Mech,
           secret = Secret,
           issued_at = Now,
           expires_at = Now + ValidityMs}.

-spec token_el(token()) -> exml:element().
token_el(#token{secret = Secret, expires_at = ExpiresAt}) ->
    #xmlel{name = <<"token">>,
          attrs = [{<<"xmlns">>, ?NS_FAST},
                   {<<"token">>, base64:encode(Secret)},
                   {<<"expiry">>, mongoose_lib:ts_to_rfc3339_bin(ExpiresAt, millisecond)}]}.

-spec feature(mongooseim:host_type()) -> exml:element().
feature(HostType) ->
    Hashes = gen_mod:get_module_opt(HostType, ?MODULE, hash),
    Mechanisms = [ <<"HT-", (Hash)/binary, "-NONE">> || Hash <- Hashes ],
    #xmlel{name = feature_name(),
           attrs = [{<<"xmlns">>, ?NS_FAST}],
           children = [ mechanism(Mech) || Mech <- Mechanisms ]}.

-spec mechanism(binary()) -> exml:element().
mechanism(Mech) ->
    #xmlel{name = <<"mechanism">>, children = [#xmlcdata{content = Mech}]}.

-spec feature_name() -> binary().
feature_name() ->
    <<"fast">>.

-spec hash_atoms() -> [atom()].
hash_atoms() ->
    [sha, sha224, sha256, sha384, sha512,
     sha3_224, sha3_256, sha3_384, sha3_512].

-spec hash_names() -> [binary()].
hash_names() ->
    [<<"SHA">>, <<"SHA-224">>, <<"SHA-256">>, <<"SHA-384">>, <<"SHA-512">>,
     <<"SHA3-224">>, <<"SHA3-256">>, <<"SHA3-384">>, <<"SHA3-512">>].

validity_to_milliseconds(#{unit := seconds, value := Value}) -> timer:seconds(Value);
validity_to_milliseconds(#{unit := minutes, value := Value}) -> timer:minutes(Value);
validity_to_milliseconds(#{unit := hours, value := Value}) -> timer:hours(Value);
validity_to_milliseconds(#{unit := days, value := Value}) -> Value * timer:hours(24).

hash_to_bin(sha) -> <<"SHA">>;
hash_to_bin(sha224) -> <<"SHA-224">>;
hash_to_bin(sha256) -> <<"SHA-256">>;
hash_to_bin(sha384) -> <<"SHA-384">>;
hash_to_bin(sha512) -> <<"SHA-512">>;
hash_to_bin(sha3_224) -> <<"SHA3-224">>;
hash_to_bin(sha3_256) -> <<"SHA3-256">>;
hash_to_bin(sha3_384) -> <<"SHA3-384">>;
hash_to_bin(sha3_512) -> <<"SHA3-512">>.
