rule SIGNATURE_BASE_Mimipenguin_1 : FILE
{
	meta:
		description = "Detects Mimipenguin hack tool"
		author = "Florian Roth (Nextron Systems)"
		id = "62754337-52ef-5d3f-af2f-52f820ba0476"
		date = "2017-07-08"
		modified = "2023-12-05"
		reference = "https://github.com/huntergregal/mimipenguin"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_mimipenguin.yar#L34-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "60a7b64eee9e2adfbc65fb5762f18e2abc4a35f9368ad704754870b5e8311391"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9e8d13fe27c93c7571075abf84a839fd1d31d8f2e3e48b3f4c6c13f7afcf8cbd"

	strings:
		$x1 = "self._strings_dump += strings(dump_process(target_pid))" fullword ascii
		$x2 = "def _dump_target_processes(self):" fullword ascii
		$x3 = "self._target_processes = ['sshd:']" fullword ascii
		$x4 = "GnomeKeyringPasswordFinder()" ascii

	condition:
		( uint16(0)==0x2123 and filesize <20KB and 1 of them )
}
