/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#define AUL_DBUS_PATH "/aul/dbus_handler"
#define AUL_DBUS_SIGNAL_INTERFACE "org.tizen.aul.signal"
#define AUL_DBUS_APPDEAD_SIGNAL	"app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL	"app_launch"
#define AUL_DBUS_HOMELAUNCH_SIGNAL	"home_launch"

#define AUL_APP_STATUS_DBUS_PATH "/Org/Tizen/Aul/AppStatus"
#define AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE "org.tizen.aul.AppStatus"
#define STATUS_FOREGROUND "fg"
#define STATUS_BACKGROUND "bg"

#define AUL_APP_STATUS_DBUS_LAUNCH_REQUEST "AppLaunch"
#define AUL_APP_STATUS_DBUS_RESUME_REQUEST "AppResume"
#define AUL_APP_STATUS_DBUS_TERMINATE_REQUEST "AppTerminate"
#define AUL_APP_STATUS_DBUS_STATUS_CHANGE "AppStatusChange"
#define AUL_APP_STATUS_DBUS_GROUP "AppGroup"
#define AUL_APP_STATUS_DBUS_TERMINATED "AppTerminated"

#define SYSTEM_PATH_CORE	"/Org/Tizen/System/DeviceD/Core"
#define SYSTEM_INTERFACE_CORE	"org.tizen.system.deviced.core"

#define SYSTEM_SIGNAL_BOOTING_DONE		"BootingDone"

#define SYSTEM_PATH_SYSNOTI	"/Org/Tizen/System/DeviceD/SysNoti"
#define SYSTEM_INTERFACE_SYSNOTI	"org.tizen.system.deviced.SysNoti"

#define SYSTEM_SIGNAL_COOLDOWN_CHANGED		"CoolDownChanged"

#define RESOURCED_PATH_CORE	"/Org/Tizen/ResourceD/Process"
#define RESOURCED_INTERFACE_CORE	"org.tizen.resourced.process"

#define RESOURCED_SIGNAL_PROCESS_STATUS		"ProcStatus"

#define ROTATION_BUS_NAME       "org.tizen.system.coord"
#define ROTATION_OBJECT_PATH    "/Org/Tizen/System/Coord/Rotation"
#define ROTATION_INTERFACE_NAME "org.tizen.system.coord.rotation"
#define ROTATION_METHOD_NAME    "Degree"

#define RESOURCED_PROC_OBJECT		"/Org/Tizen/ResourceD/Process"
#define RESOURCED_PROC_INTERFACE	"org.tizen.resourced.process"
#define RESOURCED_PROC_METHOD		"ProcExclude"

#define APPFW_SUSPEND_HINT_PATH	"/Org/Tizen/Appfw/SuspendHint"
#define APPFW_SUSPEND_HINT_INTERFACE	"org.tizen.appfw.SuspendHint"
#define APPFW_SUSPEND_HINT_SIGNAL	"SuspendHint"

#define RESOURCED_FREEZER_PATH "/Org/Tizen/Resourced/Freezer"
#define RESOURCED_FREEZER_INTERFACE	"org.tizen.resourced.freezer"
#define RESOURCED_FREEZER_SIGNAL	"FreezerState"

#define RESOURCED_ALLOWED_BG_ATTRIBUTE			0x100
#define RESOURCED_BACKGROUND_MANAGEMENT_ATTRIBUTE	0x200
#define RESOURCED_API_VER_2_4_ATTRIBUTE			0x400

#define RESOURCED_PROC_PRELAUNCH_SIGNAL "ProcPrelaunch"
#define RESOURCED_PROC_WATCHDOG_SIGNAL "ProcWatchdog"
#define RESOURCED_PROC_GROUP_SIGNAL "ProcGroup"

#define PROC_TYPE_EXCLUDE		"exclude"
#define PROC_TYPE_INCLUDE		"include"
#define PROC_TYPE_WAKEUP		"wakeup"

#define TEP_BUS_NAME "org.tizen.system.deviced"
#define TEP_OBJECT_PATH "/Org/Tizen/System/DeviceD/Tzip"
#define TEP_INTERFACE_NAME "org.tizen.system.deviced.Tzip"
#define TEP_MOUNT_METHOD "Mount"
#define TEP_UNMOUNT_METHOD "Unmount"
#define TEP_IS_MOUNTED_METHOD "IsMounted"


