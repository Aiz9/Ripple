"use client";

import Link from "next/link";

import { RippleLogo } from "@/components/ripple-logo";
import { useShallow } from "zustand/react/shallow";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
} from "@/components/ui/sidebar";
import { useCurrentUser } from "@/hooks/use-current-user";
import { sidebarItems } from "@/navigation/sidebar/sidebar-items";
import { usePreferencesStore } from "@/stores/preferences/preferences-provider";

import { NavMain } from "./nav-main";
import { NavUser } from "./nav-user";

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const currentUser = useCurrentUser();
  const { sidebarVariant, sidebarCollapsible, isSynced } = usePreferencesStore(
    useShallow((s) => ({
      sidebarVariant: s.sidebarVariant,
      sidebarCollapsible: s.sidebarCollapsible,
      isSynced: s.isSynced,
    })),
  );

  const variant = isSynced ? (sidebarVariant === "floating" ? "sidebar" : sidebarVariant) : (props.variant ?? "sidebar");
  const collapsible = isSynced ? sidebarCollapsible : props.collapsible;

  return (
    <Sidebar {...props} variant={variant} collapsible={collapsible}>
      <SidebarHeader className="h-12 shrink-0 border-b border-border p-0 gap-0">
        <Link
          prefetch={false}
          href="/android"
          className="flex h-12 w-full items-center pl-[18px] pr-4 gap-[10px] group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-0"
          aria-label="Ripple"
        >
          <RippleLogo
            width={32}
            height={32}
            className="size-8 w-8 h-8 shrink-0 flex-shrink-0 text-foreground"
          />
          <span className="text-[13px] font-semibold uppercase tracking-[0.04em] text-foreground leading-none select-none group-data-[collapsible=icon]:hidden">
            RIPPLE
          </span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={sidebarItems} />
        {/* <NavDocuments items={data.documents} /> */}
        {/* <NavSecondary items={data.navSecondary} className="mt-auto" /> */}
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={currentUser} />
      </SidebarFooter>
    </Sidebar>
  );
}
