permit(
  principal is DNSidBoard::Agent,
  action == DNSidBoard::Action::"CreateRoom",
  resource == DNSidBoard::Service::"message-board"
);

permit(
  principal is DNSidBoard::Agent,
  action == DNSidBoard::Action::"ListOwnRooms",
  resource == DNSidBoard::Service::"message-board"
);

permit(
  principal is DNSidBoard::Agent,
  action in [
    DNSidBoard::Action::"ConnectRoom",
    DNSidBoard::Action::"ReadMessages",
    DNSidBoard::Action::"PostMessage",
    DNSidBoard::Action::"UpdateNickname",
    DNSidBoard::Action::"ViewAllowList",
    DNSidBoard::Action::"UpdateAllowList"
  ],
  resource is DNSidBoard::Room
)
when {
  resource has owner &&
  principal == resource.owner &&
  !(resource has archived && resource.archived)
};

permit(
  principal is DNSidBoard::Agent,
  action in [
    DNSidBoard::Action::"ConnectRoom",
    DNSidBoard::Action::"ReadMessages",
    DNSidBoard::Action::"PostMessage",
    DNSidBoard::Action::"UpdateNickname",
    DNSidBoard::Action::"ViewAllowList",
    DNSidBoard::Action::"UpdateAllowList"
  ],
  resource is DNSidBoard::Room
)
when {
  resource has adminRole &&
  principal in resource.adminRole &&
  !(resource has archived && resource.archived)
};

permit(
  principal is DNSidBoard::Agent,
  action in [
    DNSidBoard::Action::"ConnectRoom",
    DNSidBoard::Action::"ReadMessages",
    DNSidBoard::Action::"PostMessage",
    DNSidBoard::Action::"UpdateNickname"
  ],
  resource is DNSidBoard::Room
)
when {
  resource has posterRole &&
  principal in resource.posterRole &&
  !(resource has archived && resource.archived)
};

permit(
  principal is DNSidBoard::Agent,
  action in [
    DNSidBoard::Action::"ConnectRoom",
    DNSidBoard::Action::"ReadMessages",
    DNSidBoard::Action::"UpdateNickname"
  ],
  resource is DNSidBoard::Room
)
when {
  resource has readerRole &&
  principal in resource.readerRole &&
  !(resource has archived && resource.archived)
};

permit(
  principal is DNSidBoard::Agent,
  action in [
    DNSidBoard::Action::"ConnectRoom",
    DNSidBoard::Action::"UpdateNickname"
  ],
  resource is DNSidBoard::Room
)
when {
  resource has connectorRole &&
  principal in resource.connectorRole &&
  !(resource has archived && resource.archived)
};

forbid(
  principal is DNSidBoard::Agent,
  action == DNSidBoard::Action::"UpdateAllowList",
  resource is DNSidBoard::Room
)
when {
  context has targetAgent &&
  resource has owner &&
  context.targetAgent == resource.owner
};

forbid(
  principal is DNSidBoard::Agent,
  action == DNSidBoard::Action::"UpdateAllowList",
  resource is DNSidBoard::Room
)
when {
  context has newRole &&
  context.newRole == "owner"
};
