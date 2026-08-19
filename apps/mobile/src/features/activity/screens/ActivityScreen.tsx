// Activity screen — the dedicated, power-user Audit / Explainability view
// (audit-explainability.charter.md §5: "A dedicated full audit trail view
// exists for power users who want it... not the default lens"). This is
// the ONLY screen this pass builds for that capability — the charter's
// other half (small, contextual "why/when" links scattered across other
// screens, e.g. FileDetailScreen/DevicesScreen/AccessScreen calling
// Explain inline) is explicitly out of scope for this pass (larger,
// cross-cutting follow-up, per the task brief) and is NOT built here.
//
// Zero-config default (Experience Guardian precedent, mirrors
// AccessScreen.tsx): the list just loads reverse-chronologically, no
// filtering step required. Filters (resource type, action, time range —
// audit.proto's QueryRequest fields) are available but collapsed by
// default, never forced on the user before they can see anything (charter
// §5: "mostly invisible plumbing... not a single overwhelming audit-log
// screen"). Tapping a row fetches and shows its Explain rationale inline —
// the one place this pass's brief says Explain genuinely belongs.
import * as React from "react";
import { View, Text, Pressable, ActivityIndicator, ScrollView, FlatList, TextInput } from "react-native";
import { useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList } from "../../../navigation/types";
import * as audit from "../../../capabilities/audit";
import type { AuditEvent } from "../../../capabilities/audit";
import { saveAndShareExport } from "../../../lib/export";

type ActivityRouteProp = RouteProp<RootStackParamList, "Activity">;

function formatUnixSeconds(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

/** Parses a "YYYY-MM-DD" filter input into unix seconds (start of that day, UTC), or undefined if blank/invalid — never throws, so a malformed date just means "no filter" rather than a crash. */
function parseDateFilter(value: string): number | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const ms = Date.parse(`${trimmed}T00:00:00Z`);
  if (Number.isNaN(ms)) return undefined;
  return Math.floor(ms / 1000);
}

function eventKey(e: AuditEvent, index: number): string {
  return e.eventId || `${e.action}:${e.occurredAtUnix}:${index}`;
}

export function ActivityScreen() {
  const route = useRoute<ActivityRouteProp>();
  const { identityRef, sessionToken, displayName } = route.params;

  const [events, setEvents] = React.useState<AuditEvent[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  // Filters — hidden by default (Experience Guardian: "filters available
  // but not forced on the user"), applied only when "Apply filters" is
  // pressed so the list doesn't refetch on every keystroke.
  const [filtersVisible, setFiltersVisible] = React.useState(false);
  const [resourceTypeFilter, setResourceTypeFilter] = React.useState("");
  const [actionFilter, setActionFilter] = React.useState("");
  const [sinceFilter, setSinceFilter] = React.useState("");
  const [untilFilter, setUntilFilter] = React.useState("");
  const [appliedFilters, setAppliedFilters] = React.useState<{
    resourceTypeFilter?: string;
    actionFilter?: string;
    sinceUnix?: number;
    untilUnix?: number;
  }>({});

  // Inline Explain state, keyed by eventId — the one place this pass wires
  // up Explain (charter §5's "small why/when affordance", scoped here to
  // this dedicated screen rather than other capabilities' screens).
  const [expandedEventId, setExpandedEventId] = React.useState<string | null>(null);
  const [rationaleByEventId, setRationaleByEventId] = React.useState<Record<string, string>>({});
  const [rationaleLoadingId, setRationaleLoadingId] = React.useState<string | null>(null);
  const [rationaleError, setRationaleError] = React.useState<string | null>(null);

  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  // Unsaved-fallback text (only ever populated if the OS share sheet is
  // genuinely unavailable — see saveAndShareExport) and a brief status
  // message for the normal, successful-save case. Same pattern as
  // DevicesScreen's/AccessScreen's own exports.
  const [exportFallback, setExportFallback] = React.useState<{ title: string; text: string } | null>(null);
  const [exportStatus, setExportStatus] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await audit.query(
        {
          subject: identityRef,
          resourceTypeFilter: appliedFilters.resourceTypeFilter,
          actionFilter: appliedFilters.actionFilter,
          sinceUnix: appliedFilters.sinceUnix,
          untilUnix: appliedFilters.untilUnix,
        },
        sessionToken,
      );
      setEvents(resp.events);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [identityRef, sessionToken, appliedFilters]);

  React.useEffect(() => {
    load();
  }, [load]);

  function handleApplyFilters() {
    setAppliedFilters({
      resourceTypeFilter: resourceTypeFilter.trim() || undefined,
      actionFilter: actionFilter.trim() || undefined,
      sinceUnix: parseDateFilter(sinceFilter),
      untilUnix: parseDateFilter(untilFilter),
    });
  }

  function handleClearFilters() {
    setResourceTypeFilter("");
    setActionFilter("");
    setSinceFilter("");
    setUntilFilter("");
    setAppliedFilters({});
  }

  async function handleToggleExplain(event: AuditEvent) {
    if (expandedEventId === event.eventId) {
      setExpandedEventId(null);
      return;
    }
    setExpandedEventId(event.eventId);
    setRationaleError(null);
    if (rationaleByEventId[event.eventId] !== undefined) return;

    setRationaleLoadingId(event.eventId);
    try {
      const resp = await audit.explain({ eventId: event.eventId }, sessionToken);
      setRationaleByEventId((prev) => ({ ...prev, [event.eventId]: resp.humanReadableRationale }));
    } catch (err) {
      setRationaleError(err instanceof Error ? err.message : String(err));
    } finally {
      setRationaleLoadingId(null);
    }
  }

  async function handleExportActivity() {
    setBusyAction("exportActivity");
    setExportFallback(null);
    setExportStatus(null);
    try {
      const resp = await audit.exportAuditTrail({ identityRef }, sessionToken);
      const text = new TextDecoder().decode(resp.exportBlob);
      const filename = `ascend-activity-export-${identityRef}.json`;
      const result = await saveAndShareExport(filename, text, "Save your activity export");
      if (result.shared) {
        setExportStatus(`Activity export (${resp.formatVersion}) saved as ${filename}.`);
      } else {
        setExportFallback({ title: `Activity export (${resp.formatVersion})`, text: result.text });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <View style={{ flex: 1, padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Activity</Text>
      <Text>{displayName}</Text>
      <Text style={{ color: "#666" }}>What has actually happened to your account — your own trail, in order.</Text>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        disabled={busyAction === "exportActivity"}
        onPress={handleExportActivity}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        {busyAction === "exportActivity" ? (
          <ActivityIndicator color="white" />
        ) : (
          <Text style={{ color: "white", fontWeight: "600" }}>Export my activity</Text>
        )}
      </Pressable>

      <Pressable onPress={() => setFiltersVisible((v) => !v)}>
        <Text style={{ textDecorationLine: "underline" }}>{filtersVisible ? "Hide filters" : "Filters"}</Text>
      </Pressable>

      {filtersVisible ? (
        <View style={{ borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text style={{ fontWeight: "600" }}>Narrow your trail</Text>

          <Text style={{ color: "#666" }}>Resource type</Text>
          <TextInput
            value={resourceTypeFilter}
            onChangeText={setResourceTypeFilter}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="e.g. file_object"
            style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
          />

          <Text style={{ color: "#666" }}>Action</Text>
          <TextInput
            value={actionFilter}
            onChangeText={setActionFilter}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="e.g. fileobjects.read"
            style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
          />

          <Text style={{ color: "#666" }}>Since (YYYY-MM-DD)</Text>
          <TextInput
            value={sinceFilter}
            onChangeText={setSinceFilter}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="2026-01-01"
            style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
          />

          <Text style={{ color: "#666" }}>Until (YYYY-MM-DD)</Text>
          <TextInput
            value={untilFilter}
            onChangeText={setUntilFilter}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="2026-12-31"
            style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
          />

          <View style={{ flexDirection: "row", gap: 12 }}>
            <Pressable
              onPress={handleApplyFilters}
              style={{ borderWidth: 1, borderColor: "#111", padding: 10, borderRadius: 8, alignItems: "center", flex: 1 }}
            >
              <Text>Apply filters</Text>
            </Pressable>
            <Pressable
              onPress={handleClearFilters}
              style={{ borderWidth: 1, borderColor: "#999", padding: 10, borderRadius: 8, alignItems: "center", flex: 1 }}
            >
              <Text>Clear</Text>
            </Pressable>
          </View>
        </View>
      ) : null}

      {loading ? <ActivityIndicator /> : null}

      {!loading && events.length === 0 ? (
        <ScrollView contentContainerStyle={{ paddingTop: 24, alignItems: "center", gap: 8 }}>
          <Text style={{ color: "#666" }}>No activity yet.</Text>
          <Text style={{ color: "#666", textAlign: "center" }}>
            Actions taken on your account will show up here.
          </Text>
        </ScrollView>
      ) : (
        <FlatList
          data={events}
          keyExtractor={eventKey}
          contentContainerStyle={{ gap: 8 }}
          renderItem={({ item }) => {
            const expanded = expandedEventId === item.eventId;
            return (
              <Pressable
                onPress={() => handleToggleExplain(item)}
                style={{ borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, gap: 4 }}
              >
                <Text style={{ fontWeight: "600" }}>{item.action}</Text>
                <Text style={{ color: "#666" }}>
                  {item.resource.resourceType}: {item.resource.resourceId || "—"}
                </Text>
                <Text style={{ color: "#666" }}>{formatUnixSeconds(item.occurredAtUnix)}</Text>
                <Text style={{ color: "#999", fontSize: 12 }}>{expanded ? "Hide why/when" : "Tap for why/when"}</Text>

                {expanded ? (
                  <View style={{ marginTop: 8, borderTopWidth: 1, borderTopColor: "#eee", paddingTop: 8 }}>
                    {rationaleLoadingId === item.eventId ? (
                      <ActivityIndicator />
                    ) : rationaleByEventId[item.eventId] ? (
                      <Text>{rationaleByEventId[item.eventId]}</Text>
                    ) : rationaleError ? (
                      <Text style={{ color: "#b00020" }}>{rationaleError}</Text>
                    ) : null}
                  </View>
                ) : null}
              </Pressable>
            );
          }}
        />
      )}

      {exportStatus ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text>{exportStatus}</Text>
          <Pressable onPress={() => setExportStatus(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </View>
      ) : null}

      {exportFallback ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text style={{ fontWeight: "600" }}>{exportFallback.title}</Text>
          <Text>Saving/sharing isn't available on this device — here's the export text to copy manually.</Text>
          <Text selectable style={{ fontFamily: "monospace", fontSize: 12 }}>
            {exportFallback.text}
          </Text>
          <Pressable onPress={() => setExportFallback(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </View>
      ) : null}
    </View>
  );
}
