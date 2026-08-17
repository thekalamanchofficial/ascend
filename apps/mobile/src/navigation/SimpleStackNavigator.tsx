// A minimal, headless custom stack navigator built directly on React
// Navigation's own primitives (useNavigationBuilder + StackRouter +
// createNavigatorFactory, all re-exported from "@react-navigation/native" —
// see that package's index.js: "export * from '@react-navigation/core'",
// and core's own "export * from '@react-navigation/routers'"). No new npm
// dependency was added for this: @react-navigation/native (already a
// dependency, see apps/mobile/package.json) transitively re-exports
// everything StackRouter-based navigation needs.
//
// Deliberately NOT @react-navigation/native-stack: that package requires
// react-native-screens and react-native-safe-area-context, neither of
// which are installed, and pulling them in is a real native-module/config
// change out of scope for this pass ("wiring, not polish" — see this
// module's own decision-log entry, docs/DECISION_LOG.md, 2026-08-17).
// This navigator renders only the currently-focused screen with no
// transition animation or gesture handling — functionally a stack (back
// navigation, route params, one focused screen at a time) without the
// native-stack package's visual polish. A follow-up pass can swap this out
// for @react-navigation/native-stack with no change to screen code, since
// screens only ever use the standard useNavigation()/useRoute() hooks.
import * as React from "react";
import { View } from "react-native";
import { createNavigatorFactory, useNavigationBuilder, StackRouter } from "@react-navigation/native";
import type { ParamListBase } from "@react-navigation/native";

// This custom navigator's job is narrow (render exactly one focused
// screen, headlessly) and its typing surface is entirely internal — no
// screen or app code imports SimpleStackNavigatorImpl directly, only the
// fully-typed createSimpleStackNavigator<ParamList>() factory below, whose
// return type IS precisely typed (screens/AppNavigator.tsx get real
// autocomplete and param-shape checking). react-navigation's own official
// "custom navigator" guide types this exact pattern loosely/with `any` at
// the useNavigationBuilder/createNavigatorFactory call sites for the same
// reason: the generic constraints these two functions expect don't have a
// clean instantiation for a screenOptions-agnostic, event-map-agnostic
// navigator like this one.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function SimpleStackNavigatorImpl({ initialRouteName, children, screenOptions }: any) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { state, descriptors, NavigationContent } = useNavigationBuilder(StackRouter as any, {
    children,
    screenOptions,
    initialRouteName,
  });

  return (
    <NavigationContent>
      <View style={{ flex: 1 }}>
        {state.routes.map((route, index) => {
          if (index !== state.index) return null; // only the focused screen is mounted/visible
          return (
            <View key={route.key} style={{ flex: 1 }}>
              {descriptors[route.key].render()}
            </View>
          );
        })}
      </View>
    </NavigationContent>
  );
}

export function createSimpleStackNavigator<ParamList extends ParamListBase>() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return createNavigatorFactory(SimpleStackNavigatorImpl as any)<ParamList>();
}
