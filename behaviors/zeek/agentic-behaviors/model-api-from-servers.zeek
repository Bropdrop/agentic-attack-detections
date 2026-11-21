##! Coding-agent CLIs calling model APIs from servers (behaviors hunt 02)
##!
##! Cairn's workers are Claude Code, Codex and Pi pointed at the operator's model endpoint, often a third-party gateway
##! (DeepSeek, Alibaba DashScope, OpenRouter). ARTEX, PentAGI and CyberStrikeAI consoles call the same APIs. On a laptop
##! this is normal; from a server, container host or build agent it is worth asking about. Seen here by TLS server name,
##! so no decryption is needed. Set server_nets and allowed_ai_nets in main.zeek's export block with redef.

@load base/protocols/ssl
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server opened TLS to a model API or third-party model gateway.
        Model_API_From_Server,
    };

    ## Model APIs and gateways. Add your own approved endpoints to allowed_ai_nets instead of removing them here.
    const model_hosts: set[string] = {
        "api.deepseek.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com", "openrouter.ai",
        "api.anthropic.com", "api.openai.com", "open.bigmodel.cn", "api.moonshot.cn", "api.x.ai",
        "generativelanguage.googleapis.com", "api.mistral.ai", "api.groq.com", "api.together.xyz",
    } &redef;
}


event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
    {
    if ( ! is_client || ! is_server(c$id$orig_h) )
        return;
    for ( s in allowed_ai_nets )
        if ( c$id$orig_h in s )
            return;
    for ( i in names )
        {
        local n = to_lower(names[i]);
        if ( n in model_hosts )
            raise(c, Model_API_From_Server, fmt("%s opened TLS to model API %s", c$id$orig_h, n), n,
                  cat(c$id$orig_h, n));
        }
    }
