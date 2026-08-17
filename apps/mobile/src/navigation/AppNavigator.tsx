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
      </Stack.Navigator>
    </NavigationContainer>
  );
}
