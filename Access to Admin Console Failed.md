(_source=Okta or _source="Okta Preview")

// Extract core fields
| json field=_raw "eventType" as eventType | where %"eventType" = "user.session.access_admin_app"
| json field=_raw "actor.alternateId" as actor_ID
| json field=_raw "actor.displayName" as actor_displayName
| json field=_raw "outcome.result" as outcomeResult | where outcomeResult = "FAILURE"
| formatDate(_messageTime, "MM/dd/yyyy HH:mm zzz") as timestamp

// Output summary
| count by timestamp, actor_ID, actor_displayName, eventType, _source, outcomeResult
| sort by timestamp desc


// Mitre Att@ck
// T1078: Valid Accounts

// Mitre D3fend
// 

// Okta log search
// eventType eq "user.session.access_admin_app" AND outcome.result eq "FAILURE"
