rule SIGNATURE_BASE_LOG_Teamviewer_Connect_Russian_Keyboard_Layout
{
	meta:
		description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Russian keyboard layout"
		author = "Florian Roth (Nextron Systems)"
		id = "360a1cca-2a64-5fd8-bcde-f49e1b17281e"
		date = "2019-10-12"
		modified = "2022-12-07"
		reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/log_teamviewer_keyboard_layouts.yar#L23-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9de52ec41fb410fcff50d49eb7871eadd07b520c3cfa089e1eeecc580e610eaa"
		score = 60
		quality = 85
		tags = ""
		limit = "Logscan"

	strings:
		$x1 = "Changing keyboard layout to: 0419" ascii
		$fp1 = "Changing keyboard layout to: 04190419" ascii

	condition:
		#x1>#fp1
}
