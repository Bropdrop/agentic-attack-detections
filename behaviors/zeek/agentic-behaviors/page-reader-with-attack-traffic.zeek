##! Claude Code's page reader on your application next to attack traffic from the same address (behaviors hunt 03)
##!
##! Coding-agent workers read pages with Claude Code's WebFetch tool ("Claude-User (claude-code/<version>; ...)") and
##! attack through curl, Python and Kali tools in their shell. A Claude-User read alone means little: ordinary Claude
##! Code users send it too. The same address sending Claude-User reads and tool traffic or payloads to one host within
##! the window is a coding agent attacking that host.

@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## One address sent Claude Code page reads and attack tool traffic or payloads to the same host.
        Coding_Agent_Attacking_Site,
    };

    ## How long a page read or an attack request is remembered for pairing.
    const page_reader_window: interval = 2hr &redef;
}

type ReaderState: record {
    reader: bool &default=F;
    attack: bool &default=F;
    sample: string &default="";
};

global reader_state: table[addr, string] of ReaderState &create_expire=page_reader_window;

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig || ! c?$http )
        return;
    local ua = c$http?$user_agent ? c$http$user_agent : "";
    local host = c$http?$host ? c$http$host : cat(c$id$resp_h);
    local uri = c$http?$uri ? c$http$uri : "";
    local src = c$id$orig_h;

    if ( [src, host] !in reader_state )
        reader_state[src, host] = ReaderState();
    local st = reader_state[src, host];

    if ( /Claude-User \(claude-code\// in ua )
        st$reader = T;
    else if ( tool_user_agents in ua || payload_uri in uri )
        {
        st$attack = T;
        if ( st$sample == "" )
            st$sample = fmt("%s %s", ua, uri);
        }

    if ( st$reader && st$attack )
        raise(c, Coding_Agent_Attacking_Site,
              fmt("%s read %s with Claude Code's page reader and sent attack traffic", src, host),
              st$sample, cat(src, host));
    }
