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
