// Shared Art. 9 (export) helper — every capability's "export my data" action
// on mobile funnels through this one function, so an export always lands as
// a real, durable, usable artifact, never a screen the user has to
// copy-paste or screenshot. Extracted from
// apps/mobile/src/features/onboarding/screens/DevicesScreen.tsx (its
// original, private `saveAndShareExport`, used there for
// `handleExportIdentity`/`handleExportSessions`) so a second caller
// (`features/permissions/screens/AccessScreen.tsx`'s "Export my
// permissions") doesn't have to duplicate it — see docs/DECISION_LOG.md for
// this extraction decision. Behavior is unchanged from the original.
//
// Per apps/mobile/README.md's capability boundary, this file holds no
// capability logic — it is a pure feature-composition utility (Art. 4, 10):
// it doesn't know or care which capability produced the export bytes.
import * as FileSystem from "expo-file-system";
import * as Sharing from "expo-sharing";

/**
 * Writes `text` to a real file in app-private storage, then hands it to the
 * OS share/save sheet (the standard Expo pattern for getting a file OUT of
 * a sandboxed app on Android/iOS — there is no direct "download to
 * Downloads folder" API) so the user picks where it actually lands (Files,
 * Drive, email, etc.). Falls back to returning the text unsaved only if
 * sharing is genuinely unavailable on this device, so the caller can still
 * show something rather than the export silently going nowhere.
 */
export async function saveAndShareExport(
  filename: string,
  text: string,
  dialogTitle: string,
): Promise<{ shared: true } | { shared: false; text: string }> {
  const fileUri = `${FileSystem.documentDirectory}${filename}`;
  await FileSystem.writeAsStringAsync(fileUri, text, { encoding: FileSystem.EncodingType.UTF8 });

  if (!(await Sharing.isAvailableAsync())) {
    return { shared: false, text };
  }

  await Sharing.shareAsync(fileUri, { mimeType: "application/json", dialogTitle });
  return { shared: true };
}
