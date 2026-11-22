##! Agentic attack detections by ThreatDefence: behaviors shared by agentic attack frameworks
##! https://github.com/ThreatDefence/agentic-attack-detections
##!
##! Network versions of the cross-framework hunts in behaviors/sentinel/hunting. Each script raises a notice; tune the
##! exported sets and thresholds with redef in your local.zeek. HTTP checks need cleartext HTTP, so run Zeek behind TLS
##! decryption or inside a terminating proxy for HTTPS sites. TLS, Kerberos and connection checks work as they are.
##!
##! Set server_nets. The checks that are about servers (Model_API_From_Server, Callback_To_Prober, Out_Of_Band_Lookup)
##! stay off until you do: treating every local address as a server makes laptops and scanners fire them.
##!
##! Cluster: counts run through SumStats, which adds up every worker's share on the manager. The two checks that pair
##! different events (AI_Agent_Attacking_Site, Callback_To_Prober) share what they learn through the manager; each
##! script says how. Nothing depends on one worker seeing all of an address's connections.
##!
##! Load with:  @load ./agentic-behaviors   (from the folder that holds this directory)

@load base/frameworks/notice
@load base/frameworks/cluster
@load base/frameworks/reporter

module AgenticBehaviors;

export {
    ## Internal servers, container hosts and build agents. While this is empty the server checks are off.
    const server_nets: set[subnet] = {} &redef;

    ## Developer subnets and approved AI gateways, ignored by the model API check.
    const allowed_ai_nets: set[subnet] = {} &redef;

    ## How long to suppress repeat notices for the same source and indicator.
    const suppress_for: interval = 1hr &redef;

    ## Request URIs that carry attack payloads (same expression as the KQL hunts).
    const payload_uri: pattern =
        /(?i:union(\s|\+|%20)+select)/ | /(?i:sleep\()/ | /(?i:extractvalue)/ | /\.\.\// | /(?i:%2e%2e)/ |
        /\/etc\/passwd/ | /(?i:<script|%3cscript)/ | /\$\{/ | /\{\{/ | /\/\.git\// | /\/\.env/ |
        /(?i:wp-config)/ | /(?i:phpinfo)/ &redef;

    ## Login, admin and payment paths agents aim for.
    const sensitive_uri: pattern =
        /(?i:\/(login|signin|admin|wp-admin|wp-login|api\/auth|user\/login|account|checkout|upload))/ &redef;

    ## User agents of the attack tools agents run through their shells.
    const tool_user_agents: pattern =
        /^curl\// | /^python-requests\// | /^Python-urllib\// | /sqlmap/ | /[Nn]uclei/ | /Fuzz Faster U Fool/ |
        /Nikto/ | /dirsearch/ | /WPScan/ | /katana/ | /dalfox/ | /HeadlessChrome/ &redef;
}

## True when an address is in server_nets. Always false while server_nets is empty.
function is_server(a: addr): bool
    {
    return a in server_nets;
    }

event zeek_init()
    {
    # Said once: by the manager on a cluster, by the one process otherwise.
    if ( |server_nets| == 0 && ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER ) )
        Reporter::warning("AgenticBehaviors::server_nets is empty, so Model_API_From_Server, Callback_To_Prober and Out_Of_Band_Lookup are off. Set it with redef.");
    }

function raise(c: connection, note: Notice::Type, msg: string, sub: string, key: string)
    {
    NOTICE([$note=note, $msg=msg, $sub=sub, $conn=c, $identifier=key, $suppress_for=suppress_for]);
    }
