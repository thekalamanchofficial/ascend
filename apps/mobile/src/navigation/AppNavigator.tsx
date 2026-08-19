// Root navigator wiring the onboarding feature's screens together. Per
// apps/mobile/README.md, this file holds no capability logic — it only
// composes already-built screens, matching CLAUDE.md's "features emerge
// last as thin compositions."
import * as React from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createSimpleStackNavigator } from "./SimpleStackNavigator";
import { CreateIdentityScreen } from "../features/onboarding/screens/CreateIdentityScreen";
import { RestoreIdentityScreen } from "../features/onboarding/screens/RestoreIdentityScreen";
import { DevicesScreen } from "../features/onboarding/screens/DevicesScreen";
import { FilesListScreen } from "../features/vault/screens/FilesListScreen";
import { FileDetailScreen } from "../features/vault/screens/FileDetailScreen";
import { ShareFileScreen } from "../features/vault/screens/ShareFileScreen";
import { OpenSharedFileScreen } from "../features/vault/screens/OpenSharedFileScreen";
import { AccessScreen } from "../features/permissions/screens/AccessScreen";
import { ActivityScreen } from "../features/activity/screens/ActivityScreen";
import type { RootStackParamList } from "./types";

export type { RootStackParamList };

const Stack = createSimpleStackNavigator<RootStackParamList>();

export function AppNavigator() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="CreateIdentity">
        <Stack.Screen name="CreateIdentity" component={CreateIdentityScreen} />
        <Stack.Screen name="RestoreIdentity" component={RestoreIdentityScreen} />
        <Stack.Screen name="Devices" component={DevicesScreen} />
        <Stack.Screen name="Files" component={FilesListScreen} />
        <Stack.Screen name="FileDetail" component={FileDetailScreen} />
        <Stack.Screen name="ShareFile" component={ShareFileScreen} />
        <Stack.Screen name="OpenSharedFile" component={OpenSharedFileScreen} />
        <Stack.Screen name="Access" component={AccessScreen} />
        <Stack.Screen name="Activity" component={ActivityScreen} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
