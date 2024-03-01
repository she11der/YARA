rule SIGNATURE_BASE_LOG_Teamviewer_Connect_Chinese_Keyboard_Layout
{
	meta:
		description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Chinese keyboard layout"
		author = "Florian Roth (Nextron Systems)"
		id = "f901818b-5150-540f-b645-686c12784a38"
		date = "2019-10-12"
		modified = "2020-12-16"
		reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/log_teamviewer_keyboard_layouts.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ba3bc7cbdfc5a47f6bc4cd9049c52eb95d25465af107ae3d068ef785b714279a"
		score = 60
		quality = 85
		tags = ""
		limit = "Logscan"

	strings:
		$x1 = "Changing keyboard layout to: 0804" ascii
		$x2 = "Changing keyboard layout to: 042a"
		$fp1 = "Changing keyboard layout to: 08040804" ascii
		$fp2 = "Changing keyboard layout to: 042a042a" ascii

	condition:
		(#x1+#x2)>(#fp1+#fp2)
}
