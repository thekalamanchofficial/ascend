// Shared navigation param-list/type definitions. Split out from
// AppNavigator.tsx so screen components can import the navigation prop
// type without creating a circular import (AppNavigator imports the
// screens; screens must not import AppNavigator back).
import type { NavigationProp } from "@react-navigation/native";

export type RootStackParamList = {
  CreateIdentity: undefined;
  RestoreIdentity: undefined;
  Devices: {
    identityRef: string;
    deviceId: string;
    sessionToken: string;
    displayName: string;
  };
  Files: {
    identityRef: string;
    sessionToken: string;
    displayName: string;
  };
  FileDetail: {
    identityRef: string;
    sessionToken: string;
    fileObjectId: string;
    /**
     * Best-effort display hint carried over from wherever this screen was
     * reached (FilesListScreen's own ListFileObjects result, which does
     * carry `owner`) — GetFileMetadata's frozen response shape (charter §3)
     * has no `owner` field, so a file reached via OpenSharedFileScreen's
     * manual-ID entry has no reliable way to learn it. Never used for any
     * access-control decision (the server is the sole authority on that,
     * per every RPC's own CheckPermission/caller-mismatch checks) — display
     * only.
     */
    knownOwner?: string;
  };
  ShareFile: {
    identityRef: string;
    sessionToken: string;
    fileObjectId: string;
  };
  OpenSharedFile: {
    identityRef: string;
    sessionToken: string;
  };
  Access: {
    identityRef: string;
    sessionToken: string;
    displayName: string;
  };
  Activity: {
    identityRef: string;
    sessionToken: string;
    displayName: string;
  };
};

/**
 * Named to read naturally at call sites ("this screen's navigation prop"),
 * even though this project uses the minimal custom SimpleStackNavigator
 * (see ./SimpleStackNavigator.tsx) rather than
 * @react-navigation/native-stack — the navigation prop's shape is
 * identical either way (both are plain @react-navigation/core
 * NavigationProp instances); only the visual transition
 * implementation differs.
 */
export type NativeStackNavigationProp = NavigationProp<RootStackParamList>;
