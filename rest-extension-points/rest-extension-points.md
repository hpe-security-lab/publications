# REST Extension Points for Keylime

Permalink to latest version: https://stringlytyped.github.io/publications/rest-extension-points/

## Background

[Keylime](https://github.com/keylime/keylime) currently performs registration and verification in a fairly fixed way. This means that, to a large degree, only those use cases which have been envisioned by the Keylime community are supported, unless one modifies Keylime source code.

Some forms of extensibility are already provided, for example:

- A documented set of [REST APIs](https://keylime.readthedocs.io/en/latest/rest_apis.html) which can be used to manage resources stored by the registrar and verifier (e.g., an agent's registered identities)
- A user-provided [webhook](https://github.com/keylime/keylime/blob/d68a722b2befc5bb5796c5530837455c59a26a25/keylime.conf#L297) which is called to notify an external system of revocation events produced when an agent fails verification
- A user-provided [EK check script](https://github.com/keylime/keylime/blob/d68a722b2befc5bb5796c5530837455c59a26a25/keylime.conf#L543C1-L543C17) for implementing custom logic to verify endorsement keys (EKs) and/or EK certificates

The EK check script is called by tenant and will be superseded by a [_trust decision webhook_](https://github.com/keylime/enhancements/blob/master/103_agent-driven-attestation.md#webhook-mechanism-for-custom-trust-decisions) which is invoked by the registrar and provides a more general mechanism that applies to any identity supported by the registrar.

Previous proposals[^tee-boot-prop] [^spire-prop] have contemplated extensions to Keylime which go beyond Keylime's core purpose of (1) collecting attestations, (2) performing verification thereof, (3) reporting the results of that verification, and (4) performing these three tasks in a cryptographically sound and secure manner. As the possible use cases for a general attestation tool like Keylime are so diverse, it is likely not feasible for the Keylime community to directly support and maintain functionality which implements these integrations ourselves.

However, attestation and verification is most compelling when done in concert with various other systems, including key brokers, hardware inventory systems, workload identity systems and cloud service providers (CSPs), to name only a few. Keylime should endeavour to provide well-specified mechanisms for extending Keylime core behaviour to allow the end user to hook it up to their wider infrastructure or even implement their own custom logic.


## Proposal

One way of providing such extensibility would be to continue the established Keylime practice of permitting integrations through an HTTP interface, e.g., webhook URIs which are called at various points in the registration and verification lifecycle. This approach has a number of advantages:

- Allows integration with external systems which could be running in separate containers, VMs, or even data centres, with communication potentially taking place across NAT or firewall boundaries.
- Integration with processes on the same host are also possible, with HTTP communication taking place over a loopback interface.
- The external system can be written in any language, run on any OS and hardware, and be implemented using any library available to the developer (whereas Keylime components can only be implemented using those Python libraries packaged by the supported Linux distros).
- REST-based extension points are easy and quick to implement.


### Limitations

There are however situations for which this REST-based extension framework would be inappropriate, for instance:

- For implementing new modules or components shipped with Keylime itself or maintained by the Keylime community (or to modularise Keylime's existing features). We should not force users into having to maintain a complex array of interconnected microservices to use core functionality.
- For implementing any functionality that would be better served by storing additional data within the registrar or verifier beyond simple metadata, possibly with additional [models](https://github.com/keylime/keylime/blob/master/keylime/models/base/basic_model.py) defined to handle mutation of data objects.
- For most cases in which you want the agent to collect additional data to be consumed by the registrar or verifier.

For these scenarios (and possibly others), we should support a proper plugin framework with a defined interface, so that additional modules can be loaded into Keylime itself to change how it performs registration and verification. These would be similar in nature to the [node and workload attestor plugins](https://spiffe.io/docs/latest/planning/extending/) supported by SPIRE. Additionally, existing supported identities (EK, AK, IDevID, IAK, etc.) and verification abilities (TPM-based IMA and UEFI verification) should ideally themselves be re-implemented in this plugin architecture.

Implementing these architectural changes requires work beyond what is considered in this document and should be explored in a separate proposal.

### Extension Points

The REST interfaces we should support to enable the above-described extensibility are given below:

#### Trust Decisions Webhook

Allows an external web service to provide additional identities (keys and/or certificates) which the agent itself was not able to obtain for whatever operational reason and/or override trust decisions reached by the registrar by performing verification of the available identities using the user's own custom logic.

This is specified in [more detail in Enhancement 103](https://github.com/keylime/enhancements/blob/master/103_agent-driven-attestation.md#webhook-mechanism-for-custom-trust-decisions).

#### Verification Decisions Webhook

Similar to the registrar's [trust decisions webhook](#trust-decisions-webhook), allows an external service to receive a copy of the evidence processed by the verifier, modify the evidence, and/or override decisions about whether the evidence is considered to have verified successfully and/or whether the evidence is deemed authentic.

#### Events Subscription API

Allows an external service to declare its interest in a particular set of events and receive notifications when those events occur. Typically, these would be notifications of resource change events, when a REST resource available through the verifier and registrar APIs is created, updated or deleted. Support for specific resources can be added in a piecemeal fashion over time.

To subscribe to an event, an external service makes a POST request to the events subscription endpoint (`/v3/events/subscriptions`), providing the events subscription resource it wishes to create, for example:

```json
{
    "data": {
        "type": "events_subscription",
        "attributes": {
            "event_category": "resource_event",
            "event_type": "resource_created",
            "resources": ["/agents"],
            "notify_uri": "https://ext.example.com/notifications"
        }
    }
}
```

This causes notifications to be sent by issuing a POST request to `https://ext.example.com/notifications` each time an agent resource is created. This is an example of such notification:

```json
{
    "data": {
        "type": "event_notification",
        "attributes": {
            "event_category": "resource_event",
            "event_type": "resource_created",
            "subscription_id": "541",
            "resource": "https://registrar.example.com/v3/agents/123",
            "resource_data": {
                "agent_id": "123",
                "aik_tpm": "...",
                "ek_tpm": "...",
                "ekcert": "...",
                "ip": "192.168.0.25",
                "port": "9002"
            },
            "generated_at": "2024-07-31T14:30:19.567621"
        }
    }
}
```

After creation, an events subscription is located at `/v3/events/subscriptions/:id` where `:id` is the events subscription ID. Events subscriptions can be managed by issuing GET, POST or DELETE requests to this endpoint.

An end user may also use the Keylime tenant CLI to create and manage events subscriptions.

The details of the events subscription API are provided in the below [Events Subscription API Specification](#events-subscription-api-specification).


## Events Subscription API Specification

The Events Subscription API conforms to the [JSON:API](https://jsonapi.org/) specification.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

### 1. API Endpoints

#### 1.1. Management APIs

Endpoints for managing events subscriptions should be supported by both the registrar and the verifier, namely:

- `GET /v3/events/subscriptions/`: Retrieves a list of all active events subscriptions on the server
- `POST /v3/events/subscriptions/`: Creates a new events subscription
- `GET /v3/events/subscriptions/:id`: Gets the details of a specific events subscription
- `PUT /v3/events/subscriptions/:id`: Updates the details of a specific events subscription
- `DELETE /v3/events/subscriptions/:id`: Deletes a specific events subscription

In all cases, when a request succeeds, the response issued by the server **MUST** adhere to the JSON:API [top-level document structure](https://jsonapi.org/format/#document-top-level) with the top-level `data` member set to an [events subscriptions object](#3-events-subscriptions-object). The one exception is replies produced as a result of a successful GET request to `/v3/events/subscriptions/` which **MUST** contain a `data` member with an array of [events subscriptions objects](#3-events-subscriptions-object).

POST and PUT requests to create or update an events subscription **MUST** contain a JSON payload in the request body which adheres to the JSON:API [top-level document structure](https://jsonapi.org/format/#document-top-level) with the top-level `data` member set to an [events subscriptions object](#3-events-subscriptions-object).

#### 1.2. External Service Endpoints

An external service which wishes to receive events notifications can have any number of events notification endpoints. These endpoints **MUST** all accept POST requests containing a JSON payload in the request body which adheres to the JSON:API [top-level document structure](https://jsonapi.org/format/#document-top-level) with the top-level `data` member set to an [event notification object](#4-event-notification-object).

### 2. Event Categories and Types

Events are identified by a combination of `event_category` and `event_type`. The values of these members **MUST** adhere to same constraints as a [member name](https://jsonapi.org/format/#document-member-names).

The possible values for `event_category` are as follows (these may be expanded in the future):

- `resource_event`: Events caused by a change to a resource
- `trust_decision_event`: Events caused in the course of the registrar deciding whether to trust an identity
- `verification_decision_event`: Events caused in the course of the verifier deciding whether an attestation should pass verification

For a `resource_event`, these are accepted `event_type` values (which may not all be supported for every resource):

- `resource_created`: Events caused by a resource being created
- `resource_updated`: Events caused by a resource being updated
- `resource_deleted`: Events caused by a resource being deleted

A `trust_decision_event` or `verification_decision_event` only have a single possible `event_type` value: `final_decision_reached`.

### 3. Events Subscriptions Object

An events subscription object **MUST** have the following members:

- `event_category`
- `event_type`
- `notify_uri`: The endpoint URI where the external service will receive notifications

It **MUST** also have an `id` member set to an auto-incrementing integer except when the object represents a new events subscription to be created on the server. In such case, the `id` **MUST NOT** be present in the request to create the subscription.

Additionally, an events subscription could have additional members depending on the `event_category` and `event_type`:

#### 3.1. Resource Events Subscriptions

An events subscription with an `event_category` of `resource_event` **MUST** have a `resources` member containing an array of resource URIs. These may be relative or absolute URIs, e.g., all the following forms refer to the same resource:

- `https://registrar.example.com/v3/agents/123`
- `/v3/agents/123`
- `/agents/123`

The API version, if included, is ignored.

The external service may subscribe to events related to a specific resource, e.g., a specific agent (`/agents/123`), or to a collection of resources, e.g., all agents (`/agents`). The resource being subscribed to does not need to exist at the time that the subscription is created, e.g., an external service can subscribe to `/agents/123` before creation to be notified when agent 123 registers for the first time.

When multiple resource URIs are included in the array, they **MUST** all be of the same resource type. For instance, a subscription which includes `/agents/123` and `/policy/456` would be invalid. 

The server **MUST** reject events subscriptions for resources and collections of resources which do not exist in the current API version or which do not currently support events subscriptions.

##### 3.1.1. Resource Updated Subscriptions

An events subscription with an `event_category` of `resource_event` and an `event_type` of `resource_updated` **MAY** have a `fields` member containing either an array of strings or the value `all`. When the `fields` member is not present, the value of `all` is assumed. When an array is provided, a notification will only be generated when one of the named fields included in the array change.

#### 3.2. Trust Decision Events Subscriptions

TODO.

#### 3.3. Verification Decision Events Subscriptions

TODO.

### 4. Event Notification Object

An events notification object **MUST** have the following members:

- `event_category`
- `event_type`
- `subscription_id`: The ID of the events subscription which produced the notification
- `generated_at`: The UTC time at which the notification was generated represented in the ISO 8601 format with microsecond precision

Additionally, an events notification could have additional members, depending on the `event_category` and `event_type`:

#### 4.1. Resource Event Notifications

An events notification with an `event_category` of `resource_event` **MUST** have a `resource` member containing the absolute URI of the resource which triggered the event notification (e.g., `https://registrar.example.com/v3/agents/123`).

##### 4.1.1. Resource Created Notifications

An events subscription with an `event_category` of `resource_event` and an `event_type` of `resource_created` **MUST** have a `resource_contents` member with the contents of the newly created resource.

##### 4.1.2. Resource Updated Notifications

An events subscription with an `event_category` of `resource_event` and an `event_type` of `resource_updated` **MUST** have a `resource_contents` member with the new contents of the resource as updated. Additionally, it **MUST** have a `changed_fields` member containing an object with the following structure:

```json
{
    "changed_fields": {
        "ip": {
            "previous_value": "192.168.0.25",
            "new_value": "192.168.0.26"
        }
    }
}
```

##### 4.1.3. Resource Deleted Notifications

An events subscription with an `event_category` of `resource_event` and an `event_type` of `resource_deleted` **MUST** have a `resource_contents` member with the contents of the resource at the time of deletion.

#### 4.2. Trust Decision Event Notifications

TODO.

#### 4.3. Verification Decision Event Notifications

TODO.


<br><br>

**Footnotes**

[^tee-boot-prop]: [Enhancement 107: TEE Boot Attestation](https://github.com/keylime/enhancements/blob/5140a6580befd8fa849405efe84375729f691da9/107-tee-boot-attestation.md)

[^spire-prop]: [Enhancement 98: SPIRE Integration](https://github.com/keylime/enhancements/blob/aa6b020798d4052345da4ac363721cecd67cc94b/98_spire_integration.md)
