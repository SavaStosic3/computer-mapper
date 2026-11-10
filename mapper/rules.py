"""What the classifier knows: categories, name rules for software, and folder rules.

Everything here is plain data so it is easy to extend. Rules are tried in order and the
first match wins, so specific rules (bloat, potentially unwanted software, runtimes) come
before broad vendor rules. Patterns are case-insensitive regular expressions searched in
an item's name, publisher and location/command (or, for folders, the folder name).

You can override any result in config.json with "category_overrides".
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------- categories

# Colors come from a categorical palette validated for colorblind separation in light and
# dark mode. They are assigned per *group* (7 groups, fixed order), never per category,
# and every swatch is shown next to its text label.
GROUPS = [
    # id, label, light color, dark color
    ("system", "System", "#2a78d6", "#3987e5"),
    ("software", "Software", "#eb6834", "#d95926"),
    ("gaming", "Gaming", "#1baf7a", "#199e70"),
    ("files", "Your files", "#eda100", "#c98500"),
    ("bloat", "Bloat & risk", "#e87ba4", "#d55181"),
    ("junk", "Cache & temp", "#008300", "#008300"),
    ("other", "Other", "#898781", "#898781"),
]

CATEGORIES = [
    # id, label, group, description
    ("windows", "Windows", "system",
     "Windows itself: system files, built-in apps, components and updates."),
    ("runtimes", "Runtimes & frameworks", "system",
     "Shared libraries other programs need (Visual C++, .NET, WebView2, DirectX). Leave these installed."),
    ("drivers", "Drivers & hardware", "system",
     "Device drivers and hardware companion apps: graphics, audio, network, chipset, peripherals."),
    ("security", "Security & privacy", "software",
     "Antivirus, Windows Security, password managers, VPNs and encryption tools."),
    ("development", "Development", "software",
     "Programming tools, SDKs, containers, WSL and your code projects."),
    ("ai", "AI tools", "software", "AI assistants, local models and their data."),
    ("internet", "Browsers & internet", "software", "Web browsers, their updaters and download tools."),
    ("communication", "Communication", "software", "Chat, email and video-call apps."),
    ("productivity", "Office & productivity", "software", "Office suites, PDF tools, notes and to-do apps."),
    ("media", "Media & creative", "software", "Music, video, photo, audio and design software."),
    ("cloud", "Cloud, sync & backup", "software", "OneDrive, Dropbox, Google Drive and backup tools."),
    ("utilities", "Utilities", "software", "Archivers, system tools, remote desktop and tweaks."),
    ("software", "Other software", "software", "Programs and app data that don't fit a more specific category."),
    ("gaming", "Gaming", "gaming", "Game stores, games, mods and game services."),
    ("bloat", "Bloat", "bloat",
     "Preinstalled extras, trials, promotional apps and helpers most people don't need."),
    ("risky", "Potentially unwanted", "bloat",
     "Software commonly flagged as potentially unwanted: adware, scare-ware 'optimizers', activation cracks."),
    ("personal", "Personal files", "files", "Your documents, downloads, pictures and folders you created."),
    ("junk", "Cache & temp", "junk",
     "Caches, temporary files, logs, crash dumps and the Recycle Bin. Apps recreate what they need."),
    ("other", "Other", "other", "Couldn't be classified."),
]
CATEGORY_IDS = [c[0] for c in CATEGORIES]
CATEGORY_LABELS = {c[0]: c[1] for c in CATEGORIES}

# ---------------------------------------------------------------- software rules

# Potentially unwanted software. (label, pattern, note)
RISKY = [
    ("Web Companion", r"\bweb ?companion\b|\badaware web\b",
     "Browser 'protection' add-on bundled with free-software installers; it changes your homepage and search settings."),
    ("ByteFence", r"\bbytefence\b",
     "Anti-malware program that is usually installed silently alongside other downloads."),
    ("Segurazo / SAntivirus", r"\bsegurazo\b|\bsantivirus\b",
     "Fake-alert antivirus bundled with downloads; known for being hard to uninstall."),
    ("PC repair scanner",
     r"\breimage\b|\brestoro\b|\bfortect\b|\boutbyte\b|\bwinthruster\b|\bmycleanpc\b|\bslimcleaner\b|"
     r"\bpc ?accelerate\b|\boptimizer ?pro\b|\bpc ?speed ?maximizer\b|\bsystweak\b|\badvanced system optimizer\b|"
     r"\bspyhunter\b|\badvanced ?systemcare\b|\bpc ?cleaner ?pro\b|\badvanced pc cleaner\b",
     "'PC repair' or 'optimizer' software that tends to exaggerate problems to sell a license."),
    ("Driver updater",
     r"\bdriver ?(booster|reviver|support|whiz|tonic|easy|genius|talent|max|detective|hub|fix)\b|\bdriverpack\b|"
     r"\b(smart|advanced) driver (care|updater)\b|\bdriver updater\b|\bpc ?helpsoft\b",
     "Third-party driver updaters can install the wrong drivers and usually upsell. Windows Update and your "
     "hardware maker already provide drivers."),
    ("Adware browser or search changer",
     r"\bonelaunch\b|\bwave ?browser\b|\bwebdiscover\b|\bshift browser\b|\bsearch ?protect\b|\bconduit\b|"
     r"\bbabylon\b|\bask toolbar\b|\bmindspark\b|\bmyway\b|\bmywebsearch\b|\bsnap\.do\b|\bdelta toolbar\b|"
     r"\bsweetpacks?\b|\bpdf ?converter ?hq\b|\bfromdoctopdf\b|\beasy ?pdf ?combine\b|\bbonzi",
     "Adware-style software that changes your browser, search engine or start page."),
    ("Hola VPN", r"\bhola\b.{0,20}\b(vpn|unblocker|better internet)\b",
     "Free 'VPN' that resells its users' connections as a proxy network."),
    ("Activation crack", r"\bkms ?pico\b|\bkms ?auto\b|\bkms_?vl_?all\b|\bkmspico\b|\baact\b|\bre-?loader\b",
     "Unofficial Windows/Office activation tools are a common way malware gets onto a PC."),
    ("uTorrent / BitTorrent", r"\butorrent\b|\bµtorrent\b|\bbittorrent\b",
     "Microsoft Defender flags these as potentially unwanted because their installers bundle offers. "
     "qBittorrent is a clean alternative."),
    ("Baidu PC Faster / hao123", r"\bbaidu ?(pc ?faster|antivirus|browser|security)\b|\bhao123\b",
     "Commonly bundled software that is widely flagged as potentially unwanted."),
]

# Bloat. (label, pattern, confidence, note)
BLOAT = [
    ("Logitech Download Assistant", r"\blogitech download assistant\b|\blogilda\b", "high",
     "Runs at every sign-in only to offer Logitech software downloads."),
    ("McAfee extras", r"\bmcafee ?(webadvisor|safe ?connect|security ?scan|livesafe|total protection|personal security)\b"
     r"|\bwebadvisor\b", "medium",
     "Usually preinstalled or bundled as a trial. Windows Security already protects this PC."),
    ("Norton extras", r"\bnorton ?(security ?scan|safe ?web|secure ?browser|private browser|power eraser|utilities)\b",
     "medium", "Usually bundled as a trial or add-on. Windows Security already protects this PC."),
    ("Bundled browser", r"\b(avast|avg|ccleaner|norton) (secure|private) browser\b|\b(avast|avg) ?safe ?price\b",
     "medium", "Browsers and shopping add-ons that security tools install alongside themselves."),
    ("Browser toolbar", r"\btoolbar\b", "medium", "Browser toolbars are almost always bundled extras."),
    ("Adobe Genuine Service", r"\badobe genuine (service|software integrity)\b", "low",
     "Checks Adobe licenses. Only needed while you use paid Adobe apps."),
    ("Java auto-updater", r"\bjava (auto )?update(r| scheduler)\b|\bjusched\b", "low",
     "Background updater for Java. Most people no longer need Java in the browser."),
    ("Apple Software Update", r"\bapple software update\b", "low",
     "Only needed to update iTunes/iCloud desktop versions; the Microsoft Store versions update themselves."),
    ("CCleaner", r"\bccleaner\b", "low",
     "Windows has built-in cleanup (Settings › System › Storage), and CCleaner's installer has bundled other offers."),
    ("WildTangent games", r"\bwildtangent\b", "high", "Preinstalled game trials and ads."),
    ("Promotional games & apps",
     r"\bcandy ?crush|\bbubble ?witch|\bfarm ?heroes|\bfarmville|\bmarch ?of ?empires|\bhidden ?city\b|"
     r"\broyal ?revolt|\bbooking\.com\b|\bamazon (assistant|1button)\b", "high",
     "Promotional apps that come preinstalled or get pushed onto new PCs."),
    ("PC maker extras",
     r"\bhp (jumpstart|connection optimizer|documentation|privacy settings|registration service|system event utility|"
     r"sure ?\w+|wolf security|audio switch|support solutions framework|customer experience|insights)\b|"
     r"\bdell (digital delivery|customer connect|mobile connect|supportassist\w*|update|power manager|optimizer)\b|"
     r"\bmy ?dell\b|\blenovo (vantage|now|welcome|utility|hotkeys|companion|service bridge|smart \w+|pen settings)\b|"
     r"\bacer (jumpstart|care center|collection|portal|quick access|user experience improvement|product registration|"
     r"configuration manager)\b|\basus (giftbox|webstorage|live ?update)\b|\bmyasus\b|\barmou?ry ?crate\b|"
     r"\bmsi (center|dragon center|app player|true color)\b|\bdragon center\b|\bsamsung (update|settings|recovery)\b|"
     r"\bcyberlink (media suite|power2go|powerdirector|powerdvd|youcam|photodirector|label print)\b|"
     r"\btoshiba (service station|recovery media|e-?manual)\b", "low",
     "Software the computer maker preinstalled. Some of it delivers driver and BIOS updates, so remove it only if "
     "you don't use it."),
]

# Everything else, in priority order. (category, label, pattern)
GENERAL = [
    ("windows", "Windows component",
     r"(?m)^(microsoft )?windows\b(?! ?(defender|security|subsystem|terminal|sdk|kits|app ?runtime|desktop runtime|"
     r"driver kit|assessment))|\bsoftlanding\b|\bwindows (update|media player|mail|photo viewer|nt|sidebar|portable "
     r"devices|application compatibility)\b|\bmicrosoft update health\b|\binternet explorer\b|\bhyper-v\b"),
    ("runtimes", "Visual C++ runtime", r"\bvisual c\+\+ .*(redistributable|runtime)|\bvc_?redist|\bvcredist"),
    ("runtimes", ".NET runtime",
     r"\.net (framework|runtime|desktop runtime|core runtime|host)|\bwindows desktop runtime\b|\basp\.net core\b|"
     r"\bmicrosoft\.netcore|\bnet\.native\b|^dotnet$"),
    ("runtimes", "WebView2", r"\bwebview ?2\b|\bedgewebview\b"),
    ("runtimes", "Game & media runtimes", r"\bdirectx\b|\bxna framework\b|\bopenal\b|\bvulkan run ?time\b|"
                                          r"\bgameinput\b|\bphysx\b"),
    ("runtimes", "Windows App runtime", r"\bwindows ?app ?runtime\b|\bwinappruntime\b|\bvclibs\b|\bui\.xaml\b"),
    ("runtimes", "Java runtime", r"\bjava(\(tm\))? ?(\d+ )?(update|runtime|se runtime)\b|\bjre\b"),
    ("security", "Windows Security",
     r"\bwindows (defender|security)\b|\bmicrosoft defender\b|\bsecurity ?health\b|\bsechealth"),
    ("security", "Password manager",
     r"\bbitwarden\b|\b1password\b|\bkeepass(xc)?\b|\blastpass\b|\bdashlane\b|\bproton ?pass\b|\benpass\b|\bnordpass\b"),
    ("security", "VPN",
     r"\bnord ?vpn\b|\bexpress ?vpn\b|\bproton ?vpn\b|\bmullvad\b|\bsurfshark\b|\bwindscribe\b|\bwireguard\b|"
     r"\bopenvpn\b|\bprivate internet access\b|\bcyberghost\b|\btunnelbear\b|\bcloudflare (warp|one)\b|\btailscale\b|"
     r"\bzerotier\b"),
    ("security", "Antivirus",
     r"\bmalwarebytes\b|\bnorton\b|\bmcafee\b|\bavast\b|\bavg\b|\bkaspersky\b|\bbitdefender\b|\beset\b|\bsophos\b|"
     r"\bavira\b|\bf-secure\b|\btrend ?micro\b|\bwebroot\b|\bpanda (dome|security)\b|\bhitmanpro\b|\bemsisoft\b|"
     r"\bcomodo\b|\bzonealarm\b|\bg ?data\b"),
    ("security", "Encryption & sign-in",
     r"\bveracrypt\b|\byubico\b|\byubikey\b|\bauthy\b|\bgpg4win\b|\bgnupg\b|\bcryptomator\b"),
    ("ai", "AI tools",
     r"\bollama\b|\blm ?studio\b|\bclaude\b|\banthropic\b|\bopenai\b|\bchatgpt\b|\bcodex\b|\bcopilot\b|\bgpt4all\b|"
     r"\bjan\.ai\b|\bllama[._ -]?cpp\b|\bllama-server\b|\bstable ?diffusion\b|\bcomfyui\b|\binvokeai\b|\bperplexity\b|"
     r"\bhuggingface\b|\bmsty\b|\bgemini\b"),
    ("development", "Developer tools",
     r"\bgit\b|\bgithub\b|\bgitlab\b|\bgitkraken|\bsourcetree\b|\btortoise ?(git|svn)\b|\bvisual studio\b|"
     r"\bvs ?code\b|\bvscode|\bvscodium\b|^code( - insiders)?$|\bjetbrains\b|\bintellij\b|\bpycharm\b|\bwebstorm\b|"
     r"\bphpstorm\b|\brider\b|\bclion\b|\bgoland\b|\bdatagrip\b|\bandroid (studio|sdk)\b|\beclipse\b|\bnetbeans\b|"
     r"\bsublime\b|\bcursor\b|\bwindsurf\b|\bzed\b"),
    ("development", "Languages & SDKs",
     r"\bpython\b|\banaconda\b|\bminiconda\b|\bconda\b|\bnode\.?js\b|\bnodejs\b|\bnvm\b|\bfnm\b|\bfast node manager\b|"
     r"\byarn\b|\bpnpm\b|\bdeno\b|\bjdk\b|\bopenjdk\b|\btemurin\b|\badoptium\b|\bcorretto\b|\bmaven\b|\bgradle\b|"
     r"\bgolang\b|\bgo programming language\b|\brustup\b|\brust\b|\bcargo\b|\bcmake\b|\bllvm\b|\bmingw|\bmsys2?\b|"
     r"\bcygwin\b|\bstrawberry ?perl\b|\bruby\b|\bphp\b|\b(\.net|dotnet) sdk\b|\bwindows (sdk|kits|driver kit|"
     r"assessment)\b|\bmicrosoft sdks\b|\bmsbuild\b|\bbuild ?tools\b|\breference assemblies\b|\buv\b|\bastral\b|"
     r"\bruff\b|\bpoetry\b|\bpipx\b|\bpyenv\b|\bjupyter\b|\bnuget\b|\bchocolatey\b|\bscoop\b|\bpowershell\b|"
     r"\bwindows terminal\b|\bwindowsterminal\b"),
    ("development", "Containers, cloud & data tools",
     r"\bdocker\b|\bpodman\b|\brancher desktop\b|\bkubernetes\b|\bkubectl\b|\bhelm\b|\bminikube\b|\bk9s\b|"
     r"\bterraform\b|\bvagrant\b|\bwsl\b|\bwindows subsystem for linux\b|\bubuntu\b|\bdebian\b|\bopensuse\b|"
     r"\bkali\b|\bazure (cli|data studio|functions|storage explorer|devops)\b|\baws (cli|command line|toolkit)\b|"
     r"\bgoogle cloud sdk\b|\bgcloud\b|\bheroku\b|\bvercel\b|\bnetlify\b|\bflyctl\b|\bngrok\b|\bpostman\b|"
     r"\binsomnia\b|\bdbeaver\b|\bsql server\b|\bssms\b|\bmysql\b|\bmariadb\b|\bpostgres(ql)?\b|\bpgadmin\b|"
     r"\bmongodb\b|\bredis\b|\bsqlite\b|\bwireshark\b|\bfiddler\b|\bgithub cli\b|\bputty\b|\bwinscp\b|"
     r"\bfilezilla\b|\bmremoteng\b|\btermius\b|\bmobaxterm\b|\bwezterm\b|\balacritty\b"),
    ("gaming", "Games & game stores",
     r"\bsteam\b|\bsteamapps\b|\bsteamlibrary\b|\bvalve\b|\bepic(\b|games|online)|\bunreal\b|\bea app\b|\belectronic arts\b|"
     r"\borigin games\b|\bubisoft\b|\buplay\b|\bbattle\.net\b|\bblizzard\b|\briot ?(games|client|vanguard)\b|"
     r"\bleague of legends\b|\bvalorant\b|\bgog ?(galaxy|\.com)\b|\brockstar\b|\bsocial club\b|\bparadox\b|"
     r"\bbethesda\b|\bxbox\b|\bminecraft\b|\bmojang\b|\broblox\b|\bfortnite\b|\bplaynite\b|\bitch\.io\b|"
     r"\bhoyoverse\b|\bmihoyo\b|\bgenshin\b|\bwargaming\b|\bwallpaper ?engine\b|\bsaved games\b|\bmy games\b|"
     r"\bgame ?bar\b|\bgaming\b|\bgameloft\b|\bnexus mods\b|\bcurseforge\b|\boverwolf\b|\bmedal\.?tv\b|"
     r"\banti-?cheat\b|\beasyanticheat\b|\bbattleye\b|\bxboxgames\b"),
    ("internet", "Web browsers",
     r"\bgoogle chrome\b|\bchrome\b|\bchromium\b|\bfirefox\b|\bmozilla\b|\bmicrosoft edge\b|\bmsedge\b|"
     r"\bedge ?(update|core|stable|beta|dev|canary)?\b|\bbrave\b|\bbravesoftware\b|\bopera\b|\bvivaldi\b|"
     r"\btor browser\b|\bwaterfox\b|\blibrewolf\b|\bthe browser company\b|\bzen browser\b|\bfloorp\b|"
     r"\bgoogle ?update(r)?\b"),
    ("internet", "Downloads & torrents",
     r"\bqbittorrent\b|\btransmission\b|\bdeluge\b|\bfree download manager\b|\binternet download manager\b|"
     r"\bjdownloader\b|\bmotrix\b"),
    ("communication", "Chat & meetings",
     r"\bdiscord\b|\bslack\b|\bmicrosoft teams\b|\bms ?teams\b|\bteams\b|\bzoom\b|\bskype\b|\bwhatsapp\b|"
     r"\btelegram\b|\bsignal\b|\bviber\b|\belement desktop\b|\bwebex\b|\bthunderbird\b|\bmailbird\b|\bem client\b|"
     r"\bguilded\b|\bmattermost\b|\brocket\.chat\b|\bwechat\b|\bmessenger\b|\bvencord\b"),
    ("productivity", "Office & documents",
     r"\bmicrosoft (office|365|word|excel|powerpoint|outlook|onenote|access|publisher|project|visio)\b|\boffice ?16\b|"
     r"\bclicktorun\b|\blibreoffice\b|\bopenoffice\b|\bonlyoffice\b|\bwps office\b|\bkingsoft\b|\badobe acrobat\b|"
     r"\bacrobat\b|\bfoxit\b|\bsumatra ?pdf\b|\bpdf24\b|\bpdf-?xchange\b|\bnotion\b|\bobsidian\b|\bevernote\b|"
     r"\btodoist\b|\btrello\b|\bgrammarly\b|\bzotero\b|\bmendeley\b|\bjoplin\b|\blogseq\b|\bxmind\b|\bmiro\b|"
     r"\bclickup\b|\basana\b|\bmsocache\b|\boutlook\b|\bonenote\b|\bsticky ?notes\b"),
    ("media", "Media & creative",
     r"\bvlc\b|\bvideolan\b|\bspotify\b|\bitunes\b|\bapple music\b|\bfoobar2000\b|\baudacity\b|\bobs[- ]?studio\b|"
     r"\bobs\b|\bstreamlabs\b|\bhandbrake\b|\bffmpeg\b|\bk-lite\b|\bcodec pack\b|\bmpc-(hc|be)\b|\bmpv\b|"
     r"\bpotplayer\b|\bkodi\b|\bplex\b|\bjellyfin\b|\bemby\b|\badobe (photoshop|premiere|illustrator|after effects|"
     r"lightroom|creative cloud|indesign|audition|media encoder|bridge|xd|animate|dreamweaver|substance)\b|"
     r"\bcreative cloud\b|\bgimp\b|\binkscape\b|\bkrita\b|\bblender\b|\bdavinci resolve\b|\bblackmagic\b|"
     r"\bpaint\.net\b|\birfanview\b|\bxnview\b|\bshotcut\b|\bkdenlive\b|\bcapcut\b|\bclipchamp\b|\bfl studio\b|"
     r"\bableton\b|\breaper\b|\bcubase\b|\bsteinberg\b|\bnative instruments\b|\bvoicemeeter\b|\bvb-audio\b|"
     r"\bcanva\b|\bfigma\b|\baffinity\b|\bcorel\b|\bmagix\b|\bvegas pro\b|\bmediamonkey\b|\bmusicbee\b|\baimp\b|"
     r"\bwinamp\b|\bcalibre\b|\bkindle\b|\baudible\b|\bnetflix\b|\bdisney\b|\bprime ?video\b|\btidal\b|\bdeezer\b|"
     r"\bamazon music\b|\byoutube music\b"),
    ("cloud", "Cloud, sync & backup",
     r"\bonedrive\b|\bdropbox\b|\bgoogle drive\b|\bdrivefs\b|\bdrive file stream\b|\bicloud\b|\bbox (drive|sync|tools)\b|"
     r"\bmega ?sync\b|\bpcloud\b|\bsync\.com\b|\bnextcloud\b|\bowncloud\b|\bsyncthing\b|\bbackblaze\b|\bidrive\b|"
     r"\bcarbonite\b|\bacronis\b|\bmacrium\b|\bveeam\b|\bresilio\b|\bproton ?drive\b|\btresorit\b"),
    ("utilities", "Utilities",
     r"\b7-?zip\b|\bwinrar\b|\bpeazip\b|\bbandizip\b|\bnanazip\b|\bwinzip\b|\bpowertoys\b|\bvoidtools\b|"
     r"\beverything search\b|\bnotepad\+\+|\btreesize\b|\bwindirstat\b|\bwiztree\b|\bsharex\b|\bgreenshot\b|"
     r"\blightshot\b|\bflameshot\b|\bautohotkey\b|\brevo uninstaller\b|\bbulk crap uninstaller\b|\brufus\b|"
     r"\bbalena ?etcher\b|\bventoy\b|\bcrystal ?disk\b|\bhwinfo\b|\bcpu-?z\b|\bgpu-?z\b|\bhwmonitor\b|\bspeccy\b|"
     r"\bteamviewer\b|\banydesk\b|\brustdesk\b|\bparsec\b|\bvirtualbox\b|\bvmware\b|\bf\.lux\b|\btranslucenttb\b|"
     r"\bstartallback\b|\bopen-?shell\b|\bflow ?launcher\b|\bditto\b|\bteracopy\b|\bfastcopy\b|\bglary\b|"
     r"\bbleachbit\b|\bsysinternals\b|\bprocess (explorer|monitor|hacker)\b|\bautoruns\b|"
     r"\bdisplay driver uninstaller\b|\bmsi afterburner\b|\brivatuner\b|\bfancontrol\b|\blibre ?hardware ?monitor\b|"
     r"\bsignalrgb\b|\bopenrgb\b|\bquick ?assist\b"),
    ("drivers", "Drivers & hardware",
     r"\bnvidia\b|\bgeforce\b|\bshadowplay\b|\bnvcontainer\b|\bnvcpl\b|\bamd\b|\bradeon\b|\bryzen\b|"
     r"\bati technologies\b|\bintel\b|\brealtek\b|\brtkaud|\blogitech\b|\blghub\b|\bg hub\b|\brazer\b|\bcorsair\b|"
     r"\bicue\b|\bsteelseries\b|\bhyperx\b|\broccat\b|\bturtle beach\b|\bjabra\b|\bsennheiser\b|\bfocusrite\b|"
     r"\belgato\b|\basus\b|\brog\b|\bgigabyte\b|\baorus\b|\bmsi\b|\basrock\b|\bwestern digital\b|"
     r"\bwd (discovery|dashboard|sync)\b|\bseagate\b|\bsamsung (magician|portable ssd|data migration|usb driver)\b|"
     r"\bcrucial\b|\bkingston\b|\bsynaptics\b|\belan\b|\bconexant\b|\bdolby\b|\bdts\b|\bnahimic\b|\bsonic studio\b|"
     r"\bwaves maxx|\bmaxxaudio\b|\bkiller (network|intelligence|control)\b|\bqualcomm\b|\bbroadcom\b|"
     r"\bmediatek\b|\bmarvell\b|\bthunderbolt\b|\bdisplaylink\b|\bepson\b|\bcanon\b|\bbrother\b|"
     r"\bhp (smart|print|scan|laserjet|deskjet|officejet|envy)\b|\bxerox\b|\blexmark\b|\bwacom\b|\btobii\b|"
     r"\bchipset\b|\bfirmware\b|\bbluetooth\b|\bserial io\b|\bmanagement engine\b|\bicls\b|"
     r"\bdynamic application loader\b|\bvirtual audio\b|\bvb-cable\b|\bsound blaster\b|\b8bitdo\b|\bds4windows\b|"
     r"\bvigem\b|\bdriver\b"),
    # broad vendor names last, so their specific products above win
    ("internet", "Google", r"^google$"),
    ("windows", "Microsoft", r"^microsoft$"),
]


def _compile(pattern: str):
    return re.compile(pattern, re.IGNORECASE)


RISKY_RX = [(label, _compile(p), note) for label, p, note in RISKY]
BLOAT_RX = [(label, _compile(p), conf, note) for label, p, conf, note in BLOAT]
GENERAL_RX = [(cat, label, _compile(p)) for cat, label, p in GENERAL]


def match_software(text: str):
    """First rule that matches text. Returns (category, label, confidence, note) or None."""
    if not text:
        return None
    for label, rx, note in RISKY_RX:
        if rx.search(text):
            return "risky", label, "high", note
    for label, rx, conf, note in BLOAT_RX:
        if rx.search(text):
            return "bloat", label, conf, note
    for cat, label, rx in GENERAL_RX:
        if rx.search(text):
            return cat, label, None, None
    return None


# ---------------------------------------------------------------- Store apps

# Exact package names (lower case). (category, confidence, note); confidence/note only for bloat.
_BUILTIN = "windows", None, None
STORE_APPS = {
    "microsoft.windowsnotepad": _BUILTIN, "microsoft.paint": _BUILTIN, "microsoft.windows.photos": _BUILTIN,
    "microsoft.screensketch": _BUILTIN, "microsoft.windowsstore": _BUILTIN, "microsoft.storepurchaseapp": _BUILTIN,
    "microsoft.desktopappinstaller": _BUILTIN, "microsoft.windowscalculator": _BUILTIN,
    "microsoft.windowscamera": _BUILTIN, "microsoft.windowsalarms": _BUILTIN,
    "microsoft.windowssoundrecorder": _BUILTIN, "microsoft.zunemusic": _BUILTIN,
    "microsoft.startexperiencesapp": _BUILTIN, "microsoftwindows.client.webexperience": _BUILTIN,
    "microsoft.winget.source": _BUILTIN, "microsoft.applicationcompatibilityenhancements": _BUILTIN,
    "microsoft.yourphone": _BUILTIN, "microsoftwindows.crossdevice": _BUILTIN, "microsoft.hevcvideoextension": _BUILTIN,
    "microsoft.av1videoextension": _BUILTIN, "microsoft.avcencodervideoextension": _BUILTIN,
    "microsoft.heifimageextension": _BUILTIN, "microsoft.mpeg2videoextension": _BUILTIN,
    "microsoft.rawimageextension": _BUILTIN, "microsoft.vp9videoextensions": _BUILTIN,
    "microsoft.webmediaextensions": _BUILTIN, "microsoft.webpimageextension": _BUILTIN,
    "microsoft.windows.devhome": ("development", None, None),
    "microsoft.widgetsplatformruntime": ("runtimes", None, None),
    "microsoft.powershell": ("development", None, None),
    "microsoft.windowsterminal": ("development", None, None),
    "microsoft.visualstudiocode": ("development", None, None),
    "microsoft.visualstudiocodeinsiders": ("development", None, None),
    "microsoft.sechealthui": ("security", None, None),
    "microsoft.microsoftedge.stable": ("internet", None, None),
    "microsoft.onedrivesync": ("cloud", None, None),
    "microsoft.outlookforwindows": ("productivity", None, None),
    "microsoft.todos": ("productivity", None, None),
    "microsoft.microsoftstickynotes": ("productivity", None, None),
    "microsoft.microsoftjournal": ("productivity", None, None),
    "microsoft.whiteboard": ("productivity", None, None),
    "microsoftcorporationii.quickassist": ("utilities", None, None),
    "microsoft.copilot": ("ai", None, None),
    "microsoft.gamingapp": ("gaming", None, None), "microsoft.xboxapp": ("gaming", None, None),
    "microsoft.xbox.tcui": ("gaming", None, None), "microsoft.xboxgameoverlay": ("gaming", None, None),
    "microsoft.xboxgamingoverlay": ("gaming", None, None), "microsoft.xboxidentityprovider": ("gaming", None, None),
    "microsoft.xboxspeechtotextoverlay": ("gaming", None, None), "microsoft.edge.gameassist": ("gaming", None, None),
    "microsoftcorporationii.windowssubsystemforlinux": ("development", None, None),
    "microsoft.windowssubsystemforlinux": ("development", None, None),
    # bloat
    "microsoft.bingnews": ("bloat", "medium", "News app that ships with Windows; the same news is in Edge and Widgets."),
    "microsoft.bingweather": ("bloat", "low", "Weather app that ships with Windows. Keep it if you use it."),
    "microsoft.bingsearch": ("bloat", "low", "Bing search add-on that ships with Windows."),
    "microsoft.bingfinance": ("bloat", "medium", "Retired Bing app."),
    "microsoft.bingsports": ("bloat", "medium", "Retired Bing app."),
    "microsoft.bingtravel": ("bloat", "medium", "Retired Bing app."),
    "microsoft.bingfoodanddrink": ("bloat", "medium", "Retired Bing app."),
    "microsoft.binghealthandfitness": ("bloat", "medium", "Retired Bing app."),
    "microsoft.gethelp": ("bloat", "low", "Microsoft's help app; support is also on the web."),
    "microsoft.getstarted": ("bloat", "medium", "'Tips' app that ships with Windows."),
    "microsoft.microsoftsolitairecollection": ("bloat", "medium", "Ad-supported card games that ship with Windows."),
    "microsoft.microsoftofficehub": ("bloat", "medium", "Shortcut app that promotes Microsoft 365 subscriptions."),
    "microsoft.people": ("bloat", "medium", "Retired People app."),
    "microsoft.skypeapp": ("bloat", "medium", "Skype was shut down in May 2025."),
    "microsoft.mixedreality.portal": ("bloat", "medium", "Only needed for Windows Mixed Reality headsets, which "
                                                         "Microsoft has discontinued."),
    "microsoft.microsoft3dviewer": ("bloat", "medium", "3D Viewer was discontinued."),
    "microsoft.print3d": ("bloat", "medium", "Print 3D was discontinued."),
    "microsoft.mspaint": ("bloat", "medium", "Paint 3D was discontinued; the regular Paint app is separate."),
    "microsoft.wallet": ("bloat", "medium", "Retired Wallet app."),
    "microsoft.messaging": ("bloat", "medium", "Retired Messaging app."),
    "microsoft.oneconnect": ("bloat", "medium", "Retired Mobile Plans app."),
    "microsoft.549981c3f5f10": ("bloat", "medium", "The Cortana app was retired."),
    "microsoft.windowsfeedbackhub": ("bloat", "low", "Sends feedback to Microsoft. Keep it if you use it."),
    "microsoft.zunevideo": ("bloat", "low", "Films & TV app. Keep it if you use it."),
    "microsoft.windowsmaps": ("bloat", "low", "Windows Maps is being retired."),
    "microsoft.powerautomatedesktop": ("bloat", "low", "Automation tool that ships with Windows. Keep it if you use it."),
    "microsoft.windowscommunicationsapps": ("bloat", "medium", "The old Mail & Calendar apps were retired in 2024."),
    "microsoftcorporationii.microsoftfamily": ("bloat", "low", "Family Safety app. Keep it if you use parental controls."),
    "microsoftteams": ("bloat", "low", "Teams (free) app that ships with Windows. Keep it if you use it."),
    "clipchamp.clipchamp": ("bloat", "low", "Video editor that ships with Windows. Keep it if you use it."),
    "7ee7776c.linkedinforwindows": ("bloat", "medium", "Promotional LinkedIn app."),
}

# Package-name prefixes (lower case): (prefix, category, confidence, note)
STORE_PREFIXES = [
    ("king.com.", "bloat", "high", "Candy Crush and other King games are installed as promotions."),
    ("a278ab0d.", "bloat", "high", "Promotional game (Gameloft)."),
    ("a278ab0d.marchofempires", "bloat", "high", "Promotional game."),
    ("gameloft", "bloat", "medium", "Promotional game."),
    ("facebook.", "bloat", "low", "Promotional app. Keep it if you use it."),
    ("bytedancepte.ltd.tiktok", "bloat", "low", "Promotional app. Keep it if you use it."),
    ("5a894077.mcafeesecurity", "bloat", "medium", "McAfee trial."),
    ("adobesystemsincorporated.adobephotoshopexpress", "bloat", "low", "Promotional app. Keep it if you use it."),
    ("2fe3cb00.picsart", "bloat", "low", "Promotional app. Keep it if you use it."),
    ("spotifyab.", "media", None, None), ("4df9e0f8.netflix", "media", None, None),
    ("disney.", "media", None, None), ("amazonvideo.", "media", None, None),
    ("realteksemiconductorcorp.", "drivers", None, None), ("nvidiacorp.", "drivers", None, None),
    ("dolbylaboratories.", "drivers", None, None), ("appuz.", "drivers", None, None),
    ("ad2f1837.", "drivers", None, None),  # HP hardware apps
    ("canonicalgrouplimited.", "development", None, None),
    ("microsoft.windowsappruntime", "runtimes", None, None), ("microsoft.winappruntime", "runtimes", None, None),
    ("microsoftcorporationii.winappruntime", "runtimes", None, None), ("microsoft.vclibs", "runtimes", None, None),
    ("microsoft.ui.xaml", "runtimes", None, None), ("microsoft.net.", "runtimes", None, None),
    ("microsoft.services.store", "runtimes", None, None), ("microsoft.directx", "runtimes", None, None),
    ("microsoftwindows.", "windows", None, None), ("windows.", "windows", None, None),
    ("microsoft.windows.", "windows", None, None),
]


def match_store_app(name: str):
    n = (name or "").lower()
    if n in STORE_APPS:
        return STORE_APPS[n]
    for prefix, cat, conf, note in STORE_PREFIXES:
        if n.startswith(prefix):
            return cat, conf, note
    return None


# ---------------------------------------------------------------- folders

# Folder positions are written relative to a drive ("\windows") or to a user profile
# ("~\appdata\local"), all lower case, so the rules work for every drive and every user.

# Exact positions. (category, why)
FOLDERS = {
    "\\windows": ("windows", "the Windows folder"),
    "\\windows\\temp": ("junk", "Windows temporary files"),
    "\\windows\\logs": ("junk", "Windows log files"),
    "\\windows\\minidump": ("junk", "crash dumps"),
    "\\windows\\livekernelreports": ("junk", "crash reports"),
    "\\windows\\softwaredistribution\\download": ("junk", "Windows Update download cache"),
    "\\windows\\system32\\drivers": ("drivers", "Windows driver folder"),
    "\\windows\\system32\\driverstore": ("drivers", "Windows driver store"),
    "\\windows.old": ("junk", "previous Windows installation"),
    "\\$windows.~bt": ("junk", "Windows upgrade files"),
    "\\$windows.~ws": ("junk", "Windows upgrade files"),
    "\\$getcurrent": ("junk", "Windows upgrade files"),
    "\\$sysreset": ("junk", "Windows reset leftovers"),
    "\\esd": ("junk", "Windows upgrade files"),
    "\\$recycle.bin": ("junk", "Recycle Bin"),
    "\\system volume information": ("windows", "System Restore and volume data"),
    "\\recovery": ("windows", "Windows recovery"),
    "\\perflogs": ("windows", "Windows performance logs"),
    "\\inetpub": ("windows", "Windows web server folder"),
    "\\documents and settings": ("windows", "compatibility link"),
    "\\boot": ("windows", "boot files"),
    "\\efi": ("windows", "boot files"),
    "\\onedrivetemp": ("cloud", "OneDrive temporary folder"),
    "\\msocache": ("productivity", "Office installation cache"),
    "\\xboxgames": ("gaming", "Xbox app games"),
    "\\program files": ("software", "Program Files"),
    "\\program files (x86)": ("software", "Program Files"),
    "\\program files\\windowsapps": ("software", "Store app installs"),
    "\\program files\\modifiablewindowsapps": ("gaming", "Store games"),
    "\\program files\\common files": ("software", "shared program files"),
    "\\program files (x86)\\common files": ("software", "shared program files"),
    "\\program files\\common files\\microsoft shared": ("windows", "Microsoft shared components"),
    "\\program files (x86)\\common files\\microsoft shared": ("windows", "Microsoft shared components"),
    "\\program files\\windows defender": ("security", "Microsoft Defender"),
    "\\program files (x86)\\windows defender": ("security", "Microsoft Defender"),
    "\\program files\\windows defender advanced threat protection": ("security", "Microsoft Defender"),
    "\\program files\\windowspowershell": ("windows", "Windows PowerShell modules"),
    "\\program files (x86)\\windowspowershell": ("windows", "Windows PowerShell modules"),
    "\\program files\\dotnet": ("runtimes", ".NET runtime"),
    "\\program files (x86)\\dotnet": ("runtimes", ".NET runtime"),
    "\\program files (x86)\\installshield installation information": ("software", "uninstall data for installed programs"),
    "\\programdata": ("software", "shared program data"),
    "\\programdata\\microsoft": ("windows", "Windows program data"),
    "\\programdata\\microsoft\\windows defender": ("security", "Microsoft Defender"),
    "\\programdata\\microsoft\\windows\\wer": ("junk", "Windows error reports"),
    "\\programdata\\package cache": ("software", "installer cache used for repairs and uninstalls"),
    "\\programdata\\packages": ("windows", "Store app data"),
    "\\programdata\\usoshared": ("windows", "Windows Update data"),
    "\\programdata\\usoprivate": ("windows", "Windows Update data"),
    "\\programdata\\softwaredistribution": ("windows", "Windows Update data"),
    "\\programdata\\ssh": ("windows", "Windows OpenSSH"),
    "\\programdata\\regid.1991-06.com.microsoft": ("windows", "Windows license tag"),
    "\\users": ("windows", "user profiles folder"),
    "\\users\\public": ("windows", "shared Public folder"),
    "\\users\\default": ("windows", "template for new user profiles"),
    "\\users\\default user": ("windows", "compatibility link"),
    "\\users\\all users": ("windows", "compatibility link"),
    "~": ("personal", "your user profile"),
    "~\\documents": ("personal", "Documents"),
    "~\\pictures": ("personal", "Pictures"),
    "~\\videos": ("personal", "Videos"),
    "~\\music": ("personal", "Music"),
    "~\\desktop": ("personal", "Desktop"),
    "~\\downloads": ("personal", "Downloads"),
    "~\\favorites": ("personal", "Favorites"),
    "~\\contacts": ("personal", "Contacts"),
    "~\\links": ("personal", "Links"),
    "~\\searches": ("windows", "saved searches"),
    "~\\3d objects": ("personal", "3D Objects"),
    "~\\saved games": ("gaming", "Saved Games"),
    "~\\documents\\my games": ("gaming", "game settings and saves"),
    "~\\source": ("development", "Visual Studio projects"),
    "~\\appdata": ("software", "app data"),
    "~\\appdata\\local\\temp": ("junk", "your temporary files"),
    "~\\appdata\\local\\crashdumps": ("junk", "crash dumps"),
    "~\\appdata\\local\\microsoft": ("windows", "Windows and Microsoft app data"),
    "~\\appdata\\roaming\\microsoft": ("windows", "Windows and Microsoft app data"),
    "~\\appdata\\local\\microsoft\\windows\\inetcache": ("junk", "web cache"),
    "~\\appdata\\local\\microsoft\\windows\\explorer": ("junk", "thumbnail and icon cache"),
    "~\\appdata\\local\\microsoft\\windows\\wer": ("junk", "error reports"),
    "~\\appdata\\local\\packages": ("software", "Store app data"),
    "~\\appdata\\local\\programs": ("software", "programs installed for your account"),
    "~\\appdata\\local\\d3dscache": ("junk", "shader cache"),
    "~\\appdata\\local\\connecteddevicesplatform": ("windows", "Windows device sync data"),
    "~\\appdata\\local\\comms": ("windows", "Windows app data"),
    "~\\appdata\\local\\publishers": ("windows", "Windows app data"),
    "~\\appdata\\local\\virtualstore": ("windows", "Windows compatibility files"),
    "~\\appdata\\local\\placeholdertilelogofolder": ("windows", "Start menu tiles"),
    "~\\appdata\\local\\peerdistrepub": ("windows", "Windows BranchCache"),
    "~\\appdata\\local\\squirreltemp": ("junk", "app installer leftovers"),
    "~\\appdata\\local\\history": ("windows", "compatibility link"),
    "~\\appdata\\local\\application data": ("windows", "compatibility link"),
    "~\\appdata\\local\\temporary internet files": ("windows", "compatibility link"),
    "~\\application data": ("windows", "compatibility link"),
    "~\\local settings": ("windows", "compatibility link"),
    "~\\my documents": ("windows", "compatibility link"),
    "~\\nethood": ("windows", "compatibility link"),
    "~\\printhood": ("windows", "compatibility link"),
    "~\\recent": ("windows", "compatibility link"),
    "~\\sendto": ("windows", "compatibility link"),
    "~\\start menu": ("windows", "compatibility link"),
    "~\\templates": ("windows", "compatibility link"),
    "~\\cookies": ("windows", "compatibility link"),
}

# Last two folder names, anywhere on disk. (category, why)
FOLDER_TAILS = {
    "microsoft\\edge": ("internet", "Microsoft Edge"),
    "microsoft\\edgecore": ("internet", "Microsoft Edge"),
    "microsoft\\edgeupdate": ("internet", "Microsoft Edge updater"),
    "microsoft\\edgewebview": ("runtimes", "WebView2 runtime"),
    "microsoft\\onedrive": ("cloud", "OneDrive"),
    "microsoft\\teams": ("communication", "Microsoft Teams"),
    "microsoft\\office": ("productivity", "Microsoft Office"),
    "microsoft\\windowsapps": ("windows", "app shortcuts for the command line"),
    "microsoft\\winget": ("windows", "Windows Package Manager"),
    "microsoft\\visualstudio": ("development", "Visual Studio"),
    "microsoft\\vscode": ("development", "VS Code"),
    "microsoft\\powershell": ("development", "PowerShell"),
    "microsoft\\windows terminal": ("development", "Windows Terminal"),
    "microsoft\\windows defender": ("security", "Microsoft Defender"),
    "google\\chrome": ("internet", "Google Chrome"),
    "google\\googleupdater": ("internet", "Google updater"),
    "google\\update": ("internet", "Google updater"),
    "google\\drivefs": ("cloud", "Google Drive"),
    "google\\drive file stream": ("cloud", "Google Drive"),
    "google\\cloud sdk": ("development", "Google Cloud SDK"),
    "google\\androidstudio": ("development", "Android Studio"),
    "mozilla\\firefox": ("internet", "Firefox"),
    "steamapps\\common": ("gaming", "Steam games"),
    "steamapps\\workshop": ("gaming", "Steam Workshop content"),
    "steamapps\\shadercache": ("junk", "Steam shader cache"),
    "steamapps\\downloading": ("junk", "unfinished Steam downloads"),
    "steamapps\\temp": ("junk", "Steam temporary files"),
}

# Positions whose subfolders are named after software vendors or apps.
VENDOR_CONTAINERS = {
    "\\", "\\program files", "\\program files (x86)", "\\program files\\common files",
    "\\program files (x86)\\common files", "\\programdata", "~", "~\\appdata\\local", "~\\appdata\\roaming",
    "~\\appdata\\locallow", "~\\appdata\\local\\programs", "~\\documents", "~\\appdata\\local\\microsoft\\winget\\packages",
}

# Folder names that mean "cache / temp / logs" anywhere outside the Windows folder.
JUNK_NAME_RX = re.compile(
    r"^(.*cache|cache.*|caches|cache2|temp|tmp|logs?|crashdumps|crashpad|crashes|crash ?reports|minidump|"
    r"reportarchive|reportqueue|\$recycle\.bin|squirreltemp|_cacache|__pycache__|\.pytest_cache|\.mypy_cache|"
    r"\.ruff_cache|\.tox|\.parcel-cache|\.turbo)$",
    re.IGNORECASE,
)
# ...except these, which only look like caches.
NOT_JUNK_NAMES = {"package cache", "cachedfiles"}

# Folder names that belong to code projects (applied inside your own folders only).
DEV_FOLDER_NAMES = {
    "node_modules", ".git", ".venv", "venv", ".svn", ".hg", "site-packages", ".next", ".nuxt", ".gradle", ".idea",
    ".vs", ".vscode", ".terraform", ".angular", ".svelte-kit", "bower_components",
}
# Folder names at a drive root or in your profile that hold code.
DEV_ROOT_NAMES = {"src", "source", "dev", "code", "projects", "repos", "git", "github", "workspace", "workspaces",
                  "go", "work"}
# Files that mark a folder as a code project.
PROJECT_MARKER_FILES = {
    "package.json", "pyproject.toml", "setup.py", "requirements.txt", "cargo.toml", "go.mod", "pom.xml",
    "build.gradle", "build.gradle.kts", "composer.json", "gemfile", "cmakelists.txt", "deno.json", "makefile",
}
PROJECT_MARKER_EXTS = {"sln", "csproj", "vcxproj", "fsproj"}

# Words too common to identify the software a folder belongs to.
STOPWORDS = {
    "program", "programs", "files", "file", "data", "app", "apps", "application", "applications", "common",
    "corporation", "corp", "inc", "llc", "ltd", "gmbh", "software", "the", "and", "for", "microsoft", "windows",
    "x64", "x86", "amd64", "win64", "win32", "update", "updater", "service", "services", "helper", "client",
    "desktop", "user", "users", "local", "roaming", "system", "setup", "installer", "install", "tools", "tool",
    "cache", "temp", "logs", "log", "settings", "config", "package", "packages", "runtime", "driver", "drivers",
    "version", "technologies", "technology", "systems", "group", "limited", "company", "studio", "games", "game",
    "online", "launcher", "center", "manager", "suite", "free", "pro", "plus", "lite", "beta", "preview", "insider",
    "insiders", "new", "old", "bin", "lib", "share", "shared", "ii", "co", "de", "com", "www", "net", "org",
    "exe", "dll", "lnk", "programdata", "appdata", "info", "information", "default", "public", "my", "server",
    "host", "task", "files", "unins000", "uninstall", "uninst", "data",
}
# Two-letter vendor tokens worth keeping despite their length.
SHORT_TOKENS = {"hp", "uv", "ea", "wd", "ms"}
