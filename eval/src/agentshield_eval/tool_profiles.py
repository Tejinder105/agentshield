"""Per-tool Agent Shield security classifications for AgentDojo's four
default suites (workspace, slack, travel, banking).

AgentDojo's own `Function` model carries no notion of information-flow
label, trifecta leg, or egress risk -- it is just a name, a description,
and a typed argument schema. Wiring the real `agentshield_gateway`
decision pipeline in front of it (see `agentshield_eval.harness`)
therefore requires an explicit judgment call, per tool, about:

1. What label a *successful call* to this tool should be treated as
   having read (`read_label`), which the pipeline then folds into the
   session's accumulated `current_label` ceiling check for every later
   call (pipeline step 5). AgentDojo gives this harness no per-argument
   taint tracking the way `agentshield-sdk`'s middleware does for a real
   agent framework, so a tool-level label is the closest honest
   approximation available: "calling this tool is equivalent to reading
   something at this label."
2. Which lethal-trifecta leg (if any) calling this tool acquires
   (`ToolSecurityProfile.trifecta_leg`, pipeline step 6).
3. What ceiling this tool's own call should be judged against
   (`ToolSecurityProfile.ceiling`, pipeline step 5) -- i.e. how much
   accumulated taint the session may already carry before this specific
   tool refuses to run.

The scheme applied uniformly across all four suites:

- Pure reads of the user's own sensitive data (bank balance, IBAN,
  personal info, the file system) -> `PRIVATE_DATA` leg, `read_label =
  Label.private()`, ceiling left at `Label.top()` (reading your own data
  is never blocked by *this* check -- Cedar and capabilities still gate
  it).
- Reads of content that is plausibly attacker-controlled in AgentDojo's
  own injection model -- email bodies, chat/channel messages, web pages,
  and the free-text review/description fields the travel suite injects
  into -> `UNTRUSTED_INPUT` leg, `read_label = Label.untrusted()`,
  ceiling left at `Label.top()`.
- True egress sinks -- anything that sends a message, posts to the web,
  moves money, or grants external access -> `EXTERNAL_COMMUNICATION` leg,
  and a ceiling of `(TENTATIVE, INTERNAL)`: the session's integrity must
  not have bottomed out at fully `UNTRUSTED` and its confidentiality must
  not have risen to `PRIVATE`/`SECRET`. This is deliberately *not* the
  strictest possible ceiling (`Label.bottom()`): a session that has done
  nothing but read one unread email should not already be locked out of
  ever sending a reply, or benign utility collapses to near zero before
  any attack is even run (see the ablation and over-defense measurements
  in `agentshield_eval.metrics` / `agentshield_eval.agentdyn`).
- Everything else (purely structural metadata reads, in-place mutations
  of the user's own calendar/files with no external reach) -> no leg, no
  read label, ceiling `Label.top()`: not a pillar-5/6 concern at all,
  still subject to Cedar (step 4) and capabilities (step 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentshield_core.labels import Confidentiality, Integrity, Label
from agentshield_core.trifecta import TrifectaLeg
from agentshield_gateway.registry import ToolSecurityProfile

#: Ceiling applied to every true egress sink. Blocks a session that has
#: gone fully untrusted-integrity or has touched private/secret data, but
#: tolerates the common benign case of "read one message, then reply."
EGRESS_CEILING = Label(integrity=Integrity.TENTATIVE, confidentiality=Confidentiality.INTERNAL)


@dataclass(frozen=True, slots=True)
class ToolSecurityClass:
    """One tool's full Agent Shield classification: how this call should
    be judged (`profile`), and what label a successful call should be
    treated as having read, for the benefit of every *later* call in the
    session (`read_label`).
    """

    profile: ToolSecurityProfile = field(default_factory=ToolSecurityProfile)
    read_label: Label = field(default_factory=Label.bottom)


_NEUTRAL = ToolSecurityClass(profile=ToolSecurityProfile(ceiling=Label.top(), trifecta_leg=None))
_PRIVATE_READ = ToolSecurityClass(
    profile=ToolSecurityProfile(ceiling=Label.top(), trifecta_leg=TrifectaLeg.PRIVATE_DATA),
    read_label=Label.private(),
)
_UNTRUSTED_READ = ToolSecurityClass(
    profile=ToolSecurityProfile(ceiling=Label.top(), trifecta_leg=TrifectaLeg.UNTRUSTED_INPUT),
    read_label=Label.untrusted(),
)
_EGRESS = ToolSecurityClass(
    profile=ToolSecurityProfile(
        ceiling=EGRESS_CEILING, trifecta_leg=TrifectaLeg.EXTERNAL_COMMUNICATION
    ),
    read_label=Label.bottom(),
)

WORKSPACE_PROFILES: dict[str, ToolSecurityClass] = {
    # Email
    "send_email": _EGRESS,
    "delete_email": _NEUTRAL,
    "get_unread_emails": _UNTRUSTED_READ,
    "get_sent_emails": _PRIVATE_READ,
    "get_received_emails": _UNTRUSTED_READ,
    "get_draft_emails": _PRIVATE_READ,
    "search_emails": _UNTRUSTED_READ,
    "search_contacts_by_name": _PRIVATE_READ,
    "search_contacts_by_email": _PRIVATE_READ,
    # Calendar
    "get_current_day": _NEUTRAL,
    "search_calendar_events": _PRIVATE_READ,
    "get_day_calendar_events": _PRIVATE_READ,
    "create_calendar_event": _NEUTRAL,
    "cancel_calendar_event": _NEUTRAL,
    "reschedule_calendar_event": _NEUTRAL,
    "add_calendar_event_participants": _EGRESS,
    # Cloud drive
    "append_to_file": _NEUTRAL,
    "search_files_by_filename": _PRIVATE_READ,
    "create_file": _NEUTRAL,
    "delete_file": _NEUTRAL,
    "get_file_by_id": _PRIVATE_READ,
    "list_files": _PRIVATE_READ,
    "share_file": _EGRESS,
    "search_files": _PRIVATE_READ,
}

SLACK_PROFILES: dict[str, ToolSecurityClass] = {
    "get_channels": _NEUTRAL,
    "add_user_to_channel": _EGRESS,
    "read_channel_messages": _UNTRUSTED_READ,
    "read_inbox": _UNTRUSTED_READ,
    "send_direct_message": _EGRESS,
    "send_channel_message": _EGRESS,
    "get_users_in_channel": _NEUTRAL,
    "invite_user_to_slack": _EGRESS,
    "remove_user_from_slack": _EGRESS,
    "get_webpage": _UNTRUSTED_READ,
    "post_webpage": _EGRESS,
}

TRAVEL_PROFILES: dict[str, ToolSecurityClass] = {
    "get_user_information": _PRIVATE_READ,
    "get_all_hotels_in_city": _NEUTRAL,
    "get_hotels_prices": _NEUTRAL,
    "get_rating_reviews_for_hotels": _UNTRUSTED_READ,
    "get_hotels_address": _NEUTRAL,
    "get_all_restaurants_in_city": _NEUTRAL,
    "get_cuisine_type_for_restaurants": _NEUTRAL,
    "get_restaurants_address": _NEUTRAL,
    "get_rating_reviews_for_restaurants": _UNTRUSTED_READ,
    "get_dietary_restrictions_for_all_restaurants": _NEUTRAL,
    "get_contact_information_for_restaurants": _UNTRUSTED_READ,
    "get_price_for_restaurants": _NEUTRAL,
    "check_restaurant_opening_hours": _NEUTRAL,
    "get_all_car_rental_companies_in_city": _NEUTRAL,
    "get_car_types_available": _NEUTRAL,
    "get_rating_reviews_for_car_rental": _UNTRUSTED_READ,
    "get_car_fuel_options": _NEUTRAL,
    "get_car_rental_address": _NEUTRAL,
    "get_car_price_per_day": _NEUTRAL,
    "create_calendar_event": _NEUTRAL,
    "search_calendar_events": _PRIVATE_READ,
    "get_day_calendar_events": _PRIVATE_READ,
    "cancel_calendar_event": _NEUTRAL,
    "reserve_hotel": _NEUTRAL,
    "reserve_car_rental": _NEUTRAL,
    "reserve_restaurant": _NEUTRAL,
    "get_flight_information": _NEUTRAL,
    "send_email": _EGRESS,
}

BANKING_PROFILES: dict[str, ToolSecurityClass] = {
    "get_iban": _PRIVATE_READ,
    "send_money": _EGRESS,
    "schedule_transaction": _EGRESS,
    "update_scheduled_transaction": _EGRESS,
    "get_balance": _PRIVATE_READ,
    "get_most_recent_transactions": _PRIVATE_READ,
    "get_scheduled_transactions": _PRIVATE_READ,
    "read_file": _UNTRUSTED_READ,
    "get_user_info": _PRIVATE_READ,
    "update_password": _NEUTRAL,
    "update_user_info": _NEUTRAL,
}

SUITE_PROFILES: dict[str, dict[str, ToolSecurityClass]] = {
    "workspace": WORKSPACE_PROFILES,
    "slack": SLACK_PROFILES,
    "travel": TRAVEL_PROFILES,
    "banking": BANKING_PROFILES,
}


def profiles_for_suite(suite_name: str) -> dict[str, ToolSecurityClass]:
    """The hand-authored `{tool_name: ToolSecurityClass}` map for one of
    the four AgentDojo default suites.

    Raises `KeyError` for any other suite name -- there is no safe
    "unclassified" default to fall back to here, matching the gateway's
    own fail-closed stance that an unregistered tool is exactly as
    dangerous as a misregistered one.
    """
    return SUITE_PROFILES[suite_name]
