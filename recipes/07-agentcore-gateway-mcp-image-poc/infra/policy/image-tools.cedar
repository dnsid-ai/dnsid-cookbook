// Illustrative only. This file is not read by the Recipe 07 deploy or verify
// commands, and Cedar is not part of the enforced control plane for this PoC.
// See the README's "Authorization controls" section for the live controls.
permit(
  principal,
  action,
  resource
)
when {
  principal.sub == "agent.example.com" &&
  [
    "generate_image",
    "whoami_dnsid"
  ].contains(action.tool_name)
};
