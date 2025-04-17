import pymem
import pymem.process
import struct
import ctypes
import frida
import time
import threading
from typing import Callable, Any, Protocol
from .event_handling import Event
from .events import (
    EventFunctionHooked,
    EventBoostPadChanged,
    EventTypes,
    EventPlayerTick,
    EventRoundActiveStateChanged,
    EventResetPickups,
    EventGameEventStarted,
    EventKeyPressed,
    EventGameEventDestroyed,
)
from .game_objects import (
    UClass,
    UFunction,
    GameEvent,
    TArray,
    UObject,
    FNameEntry,
    FName,
    Field,
    VehiclePickupBoost,
    GameViewportClient,
)
from .frida_script import frida_script
from colorama import Fore, Back, Style, just_fix_windows_console
from tqdm import tqdm
import json
import psutil

PROCESS_NAME = "RocketLeague.exe"

# Function names to hook
FUNCTION_PICKED_UP = "Function TAGame.VehiclePickup_TA.OnPickUp"
FUNCTION_PLAYER_TICK = "Function Engine.PlayerController.PlayerTick"
FUNCTION_KEY_PRESS = "Function TAGame.GameViewportClient_TA.HandleKeyPress"
FUNCTION_BALL_CAR_TOUCH= "Function TAGame.Ball_TA.EventCarTouch"
FUNCTION_SET_VEHICLE_INPUT = "Function TAGame.Car_TA.SetVehicleInput"
FUNCTION_PICKUP_TOUCH = "Function TAGame.VehiclePickup_TA.Touch"
FUNCTION_BALL_ON_RIGID_BODY_COLLISION = "Function TAGame.Ball_TA.OnRigidBodyCollision"
FUNCTION_BOOST_PICKED_UP = "Function TAGame.VehiclePickup_Boost_TA.Idle.EndState"
FUNCTION_BOOST_RESPAWN = "Function TAGame.VehiclePickup_Boost_TA.Idle.BeginState"
FUNCTION_ROUND_ACTIVE_BEGIN = "Function TAGame.GameEvent_Soccar_TA.Active.BeginState"
FUNCTION_ROUND_ACTIVE_END = "Function TAGame.GameEvent_Soccar_TA.Active.EndState"
FUNCTION_RESET_PICKUPS = "Function TAGame.GameEvent_TA.ResetPickups"
FUNCTION_GAMEEVENT_BEGIN_PLAY = "Function TAGame.GameEvent_Soccar_TA.PostBeginPlay"
FUNCTION_GAME_EVENT_ACTIVE_TICK = "Function TAGame.GameEvent_Soccar_TA.Active.Tick"
FUNCTION_GAME_VIEWPORT_CLIENT_TICK = "Function Engine.GameViewportClient.Tick"
FUNCTION_GAME_EVENT_DESTROYED = "Function TAGame.GameEvent_Soccar_TA.Destroyed"

CLASS_CORE_OBJECT = "Class Core.Object"

# Colors for console output
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
YELLOW = Fore.YELLOW
ENDC = Style.RESET_ALL

# Default configuration with nested dictionaries for "epic" and "steam".
DEFAULT_CONFIG = {
    "epic": {
        "gnames_offset": None,
        "gobjects_offset": None
    },
    "steam": {
        "gnames_offset": None,
        "gobjects_offset": None
    }
}

# ======================= OFFSET SCANNING FUNCTIONS =========================

# Patterns for scanning memory (you can adjust these if needed)
PATTERNS = {
    'GNames_1': b"\x75\x05\xE8\x00\x00\x00\x00\x85\xDB\x75\x31",
    'GObjects_1': b"\xE8\x00\x00\x00\x00\x8B\x5D\xBF\x48",
    'GNames_2': b"\x48\x8B\x05\x6E\xDC\xFC\x01",
    'GObjects_2': b"\x48\x8B\x05\x33\xF2\x03\x02",
    'GObjects_3': b"\x48\x89\x05\x00\x00\x00\x00\x4C\x8D\x05\x00\x00\x00\x00\xBA\xFA\x02"
}

def pattern_scan(pm, module_base, module_size, pattern, pattern_name="Unknown"):
    """Scan memory for given pattern with minimal debug output."""
    try:
        print(YELLOW + f"Searching for {pattern_name}..." + ENDC)
        bytes_dump = pm.read_bytes(module_base, module_size)
        for i in range(len(bytes_dump) - len(pattern)):
            match = True
            for j in range(len(pattern)):
                # A 0x00 byte in the pattern is considered a wildcard.
                if pattern[j] != 0x00 and bytes_dump[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                found_addr = module_base + i
                print(GREEN + f"Found {pattern_name} at {hex(found_addr)}" + ENDC)
                return found_addr
        return None
    except Exception as e:
        print(RED + f"Scan failed for {pattern_name}: {e}" + ENDC)
        return None

def get_gnames_method1(pm, base_addr, pattern_addr):
    """Attempt to find GNames using method 1."""
    try:
        offset = pattern_addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        addr = offset + rel_offset + 4
        addr += 0x27  # Extra offset from forum code.
        offset = addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        final_addr = offset + rel_offset + 4
        return final_addr
    except Exception as e:
        print(RED + f"Method 1 for GNames failed: {e}" + ENDC)
        return None

def get_gobjects_method1(pm, base_addr, pattern_addr):
    """Attempt to find GObjects using method 1."""
    try:
        offset = pattern_addr + 1
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        addr = offset + rel_offset + 4
        addr += 0x65  # Extra offset from forum code.
        offset = addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        final_addr = offset + rel_offset + 4
        return final_addr
    except Exception as e:
        print(RED + f"Method 1 for GObjects failed: {e}" + ENDC)
        return None

def find_gnames_gobjects():
    """
    Attach to Rocket League and try to find GNames and GObjects offsets.
    Returns a tuple: (gnames_offset, gobjects_offset) relative to the module base.
    """
    try:
        print(YELLOW + "Attaching to Rocket League..." + ENDC)
        pm = pymem.Pymem(PROCESS_NAME)
        module = pymem.process.module_from_name(pm.process_handle, PROCESS_NAME)
        base_address = module.lpBaseOfDll
        module_size = module.SizeOfImage
        print(YELLOW + f"Module base: {hex(base_address)}" + ENDC)
        
        gnames_addr = None
        gobjects_addr = None
        
        print(YELLOW + "Searching for offsets (method 1)..." + ENDC)
        gnames_pattern_addr = pattern_scan(pm, base_address, module_size, PATTERNS['GNames_1'], "GNames")
        if gnames_pattern_addr:
            gnames_addr = get_gnames_method1(pm, base_address, gnames_pattern_addr)
            if gnames_addr:
                print(GREEN + f"GNames offset found at {hex(gnames_addr)}" + ENDC)
        
        gobjects_pattern_addr = pattern_scan(pm, base_address, module_size, PATTERNS['GObjects_1'], "GObjects")
        if gobjects_pattern_addr:
            gobjects_addr = get_gobjects_method1(pm, base_address, gobjects_pattern_addr)
            if gobjects_addr:
                print(GREEN + f"GObjects offset found at {hex(gobjects_addr)}" + ENDC)
        
        if not gnames_addr or not gobjects_addr:
            print(YELLOW + "Method 1 failed, trying alternative patterns..." + ENDC)
            for pattern_name, pattern in PATTERNS.items():
                if pattern_name.startswith('GNames_2') and not gnames_addr:
                    addr = pattern_scan(pm, base_address, module_size, pattern, pattern_name)
                    if addr:
                        rel_offset = struct.unpack("i", pm.read_bytes(addr + 3, 4))[0]
                        gnames_addr = addr + rel_offset + 7
                        print(GREEN + f"GNames offset found via {pattern_name} at {hex(gnames_addr)}" + ENDC)
                
                if pattern_name.startswith('GObjects_2') and not gobjects_addr:
                    addr = pattern_scan(pm, base_address, module_size, pattern, pattern_name)
                    if addr:
                        rel_offset = struct.unpack("i", pm.read_bytes(addr + 3, 4))[0]
                        gobjects_addr = addr + rel_offset + 7
                        print(GREEN + f"GObjects offset found via {pattern_name} at {hex(gobjects_addr)}" + ENDC)
        
        if gnames_addr and gobjects_addr:
            diff = abs(gobjects_addr - gnames_addr)
            if diff != 0x48:
                print(YELLOW + f"Offset diff {hex(diff)} unexpected; adjusting..." + ENDC)
                gnames_addr = gobjects_addr - 0x48
                print(GREEN + f"Adjusted GNames offset: {hex(gnames_addr)}" + ENDC)
            return (gnames_addr - base_address, gobjects_addr - base_address)
        
        return None, None
    except Exception as e:
        print(RED + f"Error during offset finding: {str(e)}" + ENDC)
        return None, None

# ========================== RLSDK CLASS ================================

class RLSDK:
    def __init__(self, hook_player_tick=False, pid=None):
        self.pid = pid

        # Load configuration (or use default) for Epic/Steam
        self.config = DEFAULT_CONFIG
        try:
            with open("sdk_config.json", "r") as file:
                self.config = json.load(file)
        except:
            print(RED + "Could not load sdk_config.json. Creating a new one with default settings." + ENDC)
            with open("sdk_config.json", "w") as file:
                json.dump(DEFAULT_CONFIG, file, indent=4)

        try:
            self.pm = pymem.Pymem(self.pid if self.pid else PROCESS_NAME)
            self.frida = frida.attach(self.pid if self.pid else PROCESS_NAME)
        except Exception as e:
            raise Exception(RED + "Rocket League not found. Make sure Rocket League is running." + ENDC)

        # ==========================================================
        # 1. Detect if the running RL is Steam or Epic
        # ==========================================================
        self.build_type = self.detect_build_type()
        print(YELLOW + f"Detected build type: {self.build_type.upper()}" + ENDC)

        # Retrieve offsets from config
        self.g_names_offset = self.config[self.build_type].get("gnames_offset", None)
        self.g_object_offset = self.config[self.build_type].get("gobjects_offset", None)

        # If offsets are missing, attempt auto-resolution.
        if self.g_names_offset is None or self.g_object_offset is None:
            try:
                self.resolve_offsets()
                self.config[self.build_type]["gnames_offset"] = self.g_names_offset
                self.config[self.build_type]["gobjects_offset"] = self.g_object_offset
                with open("sdk_config.json", "w") as file:
                    json.dump(self.config, file, indent=4)
            except Exception as e:
                raise Exception(RED + "Offsets not found and could not be resolved automatically." + ENDC)
        else:
            print(GREEN + f"Offsets loaded from config for {self.build_type.upper()}" + ENDC)

        # Initialize event system and related structures.
        self.event = Event()
        self.index_indexed_gnames = {}
        self.gnames = {}
        self.static_classes = {}
        self.static_functions = {}
        self.scan_result = []
        self.scan_response_received_event = threading.Event()

        # Load GNames and map objects.
        try:
            self.load_gnames()
            self.map_objects()
        except Exception as e:
            print(RED + "Error loading GNames or mapping objects. Re-resolving offsets..." + ENDC)
            try:
                self.resolve_offsets()
                self.load_gnames()
                self.map_objects()
                self.config[self.build_type]["gnames_offset"] = self.g_names_offset
                self.config[self.build_type]["gobjects_offset"] = self.g_object_offset
                with open("sdk_config.json", "w") as file:
                    json.dump(self.config, file, indent=4)
            except Exception as e:
                raise Exception(RED + "Error loading GNames and mapping objects. Offsets may be invalid." + ENDC)

        # Get ProcessEvent address.
        self.process_event_address = self.get_process_event_address()
        self.current_game_event = None
        if self.process_event_address is None:
            print(RED + "ProcessEvent address not found. Make sure Rocket League is running." + ENDC)
            return

        print(GREEN + f"ProcessEvent Address: {hex(self.process_event_address)}" + ENDC)

        # Inject Frida script.
        print(YELLOW + "Injecting Frida script..." + ENDC)
        self.frida_script = self.frida.create_script(frida_script)
        self.frida_script.load()
        self.frida_script.on("message", self.on_frida_message)
        self.frida_script.post({"type": "process_event_address", "address": self.process_event_address})

        # Setup function hooks.
        self.hook_function(FUNCTION_BOOST_PICKED_UP)
        self.hook_function(FUNCTION_BOOST_RESPAWN)
        self.hook_function(FUNCTION_ROUND_ACTIVE_BEGIN)
        self.hook_function(FUNCTION_ROUND_ACTIVE_END)
        self.hook_function(FUNCTION_RESET_PICKUPS)
        self.hook_function(FUNCTION_GAMEEVENT_BEGIN_PLAY)
        self.hook_function(FUNCTION_KEY_PRESS, args_map=[(2, "bytes", "key_params", 0x1C)])
        self.hook_function(FUNCTION_GAME_VIEWPORT_CLIENT_TICK)
        self.hook_function(FUNCTION_GAME_EVENT_DESTROYED)
        if hook_player_tick:
            self.hook_function(FUNCTION_PLAYER_TICK, args_map=[(2, "float", "deltatime")])
        self.event.subscribe(EventTypes.ON_HOOKED_FUNCTION, self.on_function_called)
        self.field = Field(self)
        print(GREEN + "SDK initialized" + ENDC)

    # ==========================================================
    #             Detect if game is STEAM or EPIC
    # ==========================================================
    def detect_build_type(self) -> str:
        """
        Detect whether the running Rocket League is Steam or Epic.
        Returns "steam" or "epic".
        """
        try:
            ps_proc = psutil.Process(self.pm.process_id)
            exe_path = ps_proc.exe().lower()
            if "epic" in exe_path:
                return "epic"
            elif "steam" in exe_path:
                return "steam"
            else:
                answer = input(RED + "Version not recognized. Are you using (1) Steam or (2) Epic? " + ENDC)
                while int(answer) != 1 and int(answer) != 2:
                    answer = input(RED + "Please enter 1 or 2: " + ENDC)
                return "steam" if int(answer) == 1 else "epic"
        except Exception as e:
            answer = input(RED + "Version not recognized. Are you using (1) Steam or (2) Epic? " + ENDC)
            while int(answer) != 1 and int(answer) != 2:
                answer = input(RED + "Please enter 1 or 2: " + ENDC)
            return "steam" if int(answer) == 1 else "epic"

    # ==========================================================
    # ================     Offsets finding     =================
    # ==========================================================
    def resolve_offsets(self):
        print(YELLOW + "Resolving offsets..." + ENDC)
        offsets = find_gnames_gobjects()
        if offsets[0] is None or offsets[1] is None:
            raise Exception("Offsets not found")
        self.g_names_offset = offsets[0]
        self.g_object_offset = offsets[1]
        print(GREEN + f"Resolved offsets: GNames: {hex(self.g_names_offset)} | GObjects: {hex(self.g_object_offset)}" + ENDC)

    def resolve_gobjects_offset(self):
        pattern = rb"\xE8....\x8B\x5D\xAF"
        base_address = self.pm.pattern_scan_all(pattern, return_multiple=False)
        if base_address is None:
            return None
        relative_offset = self.pm.read_int(base_address + 1)
        intermediate_address = base_address + 1 + relative_offset + 4
        final_relative_offset = self.pm.read_int(intermediate_address + 0x65 + 3)
        final_address = intermediate_address + 0x65 + 3 + final_relative_offset + 4
        if not final_address:
            raise Exception("GObjects offset not found")
        return final_address - self.pm.base_address

    def resolve_gnames_offset(self):
        pattern = rb"\x75.\xE8....\x48\xC7\xC7"
        base_address = self.pm.pattern_scan_all(pattern, return_multiple=False)
        if base_address is None:
            return None
        relative_offset = self.pm.read_int(base_address + 3)
        intermediate_address = base_address + 3 + relative_offset + 4
        final_relative_offset = self.pm.read_int(intermediate_address + 0x2F + 3)
        final_address = intermediate_address + 0x2F + 3 + final_relative_offset + 4
        if not final_address:
            raise Exception("GNames offset not found")
        return final_address - self.pm.base_address

    def get_process_event_address(self):
        core_object = self.find_static_class(CLASS_CORE_OBJECT)
        if core_object:
            print(GREEN + "Core Object Address: " + hex(core_object.address) + ENDC)
            vtable_address = self.pm.read_ulonglong(core_object.address)
            return self.pm.read_ulonglong(vtable_address + (0x8 * 67))
        return None

    # ==========================================================
    # ================ INTERNAL EVENT HANDLING =================
    # ==========================================================
    def on_function_called(self, event: EventFunctionHooked):
        function_name = event.function.get_full_name()
        if function_name == FUNCTION_BOOST_PICKED_UP:
            pickup = VehiclePickupBoost(int(event.args["caller"], 16), sdk=self)
            boostpad = self.field.find_boostpad_from_pickup(pickup)
            if boostpad:
                boostpad.is_active = False
                boostpad.pickup = pickup
                boostpad.picked_up_time = time.time()
                self.field.update_boostpad_from_pickup(boostpad, pickup)
                self.event.fire(EventTypes.ON_BOOSTPAD_CHANGED, EventBoostPadChanged(boostpad))
        elif function_name == FUNCTION_BOOST_RESPAWN:
            pickup = VehiclePickupBoost(int(event.args["caller"], 16), sdk=self)
            boostpad = self.field.find_boostpad_from_pickup(pickup)
            if boostpad:
                boostpad.is_active = True
                boostpad.pickup = pickup
                boostpad.picked_up_time = None
                self.field.update_boostpad_from_pickup(boostpad, pickup)
                self.event.fire(EventTypes.ON_BOOSTPAD_CHANGED, EventBoostPadChanged(boostpad))
        elif function_name == FUNCTION_PLAYER_TICK:
            self.event.fire(EventTypes.ON_PLAYER_TICK, EventPlayerTick(event.args["deltatime"]))
        elif function_name == FUNCTION_ROUND_ACTIVE_BEGIN:
            self.event.fire(EventTypes.ON_ROUND_ACTIVE_STATE_CHANGED, EventRoundActiveStateChanged(True))
        elif function_name == FUNCTION_ROUND_ACTIVE_END:
            self.event.fire(EventTypes.ON_ROUND_ACTIVE_STATE_CHANGED, EventRoundActiveStateChanged(False))
        elif function_name == FUNCTION_RESET_PICKUPS:
            self.event.fire(EventTypes.ON_RESET_PICKUPS, EventResetPickups())
            self.field.reset_boostpads()
        elif function_name == FUNCTION_GAMEEVENT_BEGIN_PLAY:
            self.event.fire(EventTypes.ON_GAME_EVENT_STARTED, EventGameEventStarted())
        elif function_name == FUNCTION_KEY_PRESS:
            params = event.args["key_params"]
            data_bytes = bytes.fromhex(params)
            fname_entry_id = int.from_bytes(data_bytes[4:8], byteorder="little")
            key_name = self.gnames[fname_entry_id]
            ev = EventKeyPressed(data_bytes, key_name)
            self.event.fire(EventTypes.ON_KEY_PRESSED, ev)
        elif function_name == FUNCTION_GAME_VIEWPORT_CLIENT_TICK:
            viewport = GameViewportClient(int(event.args["caller"], 16), sdk=self)
            self.current_game_event = viewport.get_game_event()
        elif function_name == FUNCTION_GAME_EVENT_DESTROYED:
            self.current_game_event = None
            self.event.fire(EventTypes.ON_GAME_EVENT_DESTROYED, EventGameEventDestroyed())

    # ==========================================================
    # ===================== EXTRACTION METHODS ======================
    # ==========================================================
    def extract_classes(self):
        print("Extracting classes...")
        filename = "classes.txt"
        with open(filename, "w") as file:
            for class_name, class_object in self.static_classes.items():
                file.write(hex(class_object.address) + " : " + class_name + "\n")
        print("Classes extracted to " + filename)

    def extract_functions(self):
        print("Extracting functions...")
        filename = "functions.txt"
        with open(filename, "w") as file:
            for function_name, function_object in self.static_functions.items():
                file.write(hex(function_object.address) + " : " + function_name + "\n")
        print("Functions extracted to " + filename)

    # ==========================================================
    # =================== FRIDA HOOKING METHODS ===================
    # ==========================================================
    def on_frida_message(self, message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if payload.get("type") == "hooked_function_fired":
                function = UFunction(int(payload.get("address"), 16), sdk=self)
                self.event.fire(EventTypes.ON_HOOKED_FUNCTION, EventFunctionHooked(function, payload.get("args")))
            if payload.get("type") == "scan_result":
                for f in payload.get("functions"):
                    function_address = int(f, 16)
                    self.scan_result.append(UFunction(function_address, sdk=self))
                self.scan_response_received_event.set()
            elif payload.get("type") == "log":
                print(Fore.MAGENTA + "Frida log: " + ENDC + payload.get("message"))
        else:
            print("Received message:", message)

    def hook_function(self, function_name, args_map=[]):
        fn = self.find_static_function(function_name)
        if not fn:
            return
        function_address = fn.address
        if function_address:
            self.frida_script.post({
                "type": "hook_function",
                "address": function_address,
                "name": function_name,
                "args_map": args_map,
            })

    def get_provider(self):
        pattern = rb"\xBA\xFA\x02\x00\x00\x48\x89\x05"
        base_address = self.pm.pattern_scan_all(pattern, return_multiple=False)
        if base_address is None:
            return None
        relative_offset = self.pm.read_int(base_address + 8)
        final_address = base_address + 8 + relative_offset + 4
        provider_address = self.pm.read_ulonglong(final_address)
        if not provider_address:
            return None
        tarray_base_address = provider_address + 0xD8
        tarray = TArray(tarray_base_address, UObject, sdk=self)
        return tarray

    # ==========================================================
    # =================== EXTRACTION & HELPER METHODS ============
    # ==========================================================
    def get_game_event(self):
        return self.current_game_event

    def get_field(self):
        return self.field

    def get_gobjects_tarray(self):
        return TArray(self.pm.base_address + self.g_object_offset, UObject, sdk=self)

    def get_gnames_entries_tarray(self):
        return TArray(self.pm.base_address + self.g_names_offset, FNameEntry, sdk=self)

    def get_pm(self):
        return self.pm

    def get_name(self, index):
        return self.gnames.get(index)

    def find_static_function(self, function_name):
        return self.static_functions.get(function_name)

    def find_static_class(self, class_name):
        return self.static_classes.get(class_name)

    def get_offsets_final_address(self, offsets):
        if self.pm is not None:
            base_address = self.pm.base_address
            for offset in offsets:
                base_address = self.pm.read_ulonglong(base_address + offset)
            return base_address

    def load_gnames(self):
        print(YELLOW + "Loading GNames..." + ENDC)
        gnames_entries_tarray = self.get_gnames_entries_tarray()
        print(GREEN + f"GNames count: {gnames_entries_tarray.get_count()}" + ENDC)
        for gname_entry in tqdm(gnames_entries_tarray.get_items()):
            if not gname_entry.address:
                continue
            self.gnames[gname_entry.get_index()] = gname_entry.get_name()
        print(GREEN + "GNames loaded" + ENDC)

    def map_objects(self):
        print(YELLOW + "Mapping objects..." + ENDC)
        gobjects_tarray = self.get_gobjects_tarray()
        for gobject in tqdm(gobjects_tarray.get_items()):
            if not gobject.address:
                continue
            full_name = gobject.get_full_name()
            if "Class " in full_name:
                self.static_classes[full_name] = UClass(gobject.address, sdk=self)
            elif "Function " in full_name:
                self.static_functions[full_name] = UFunction(gobject.address, sdk=self)
        print(GREEN + f"UClasses: {len(self.static_classes)}" + ENDC)
        print(GREEN + f"UFunctions: {len(self.static_functions)}" + ENDC)

    # ==========================================================
    # ===================== DEBUG METHODS ======================
    # ==========================================================
    def scan_functions(self, duration=10):
        print("Scanning functions...")
        self.scan_response_received_event.clear()
        self.frida_script.post({"type": "scan_functions", "duration": duration})
        received = self.scan_response_received_event.wait(duration + 10)
        if received:
            print("Scan result received.")
            return self.scan_result
        else:
            print("Scan timed out.")
            return None

    def dump_packet(self, game_tick_packet):
        json_packet = json.dumps(game_tick_packet.__dict__, indent=4)
        frame_num = game_tick_packet.game_info.frame_num
        with open("game_tick_packet_" + str(frame_num) + ".json", "w") as f:
            f.write(json_packet)
        print(GREEN + f"Game tick packet dumped to game_tick_packet_{frame_num}.json" + ENDC)