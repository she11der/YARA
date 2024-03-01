rule SIGNATURE_BASE_Molerats_Jul17_Sample_5 : FILE
{
	meta:
		description = "Detects Molerats sample - July 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "c9dd4f4a-a980-5339-b238-9f53360b89ae"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_molerats_jul17.yar#L78-L95"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "eb2bb54fc1749d8422cdc8e084e1fa66981611128f56e7d7d678f177d37b7cdd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"

	strings:
		$x1 = "powershell.exe -nop -c \"iex" nocase ascii
		$x2 = ".run('%windir%\\\\SysWOW64\\\\WindowsPowerShell\\\\" ascii
		$a1 = "Net.WebClient).DownloadString" nocase ascii
		$a2 = "gist.githubusercontent.com" nocase ascii

	condition:
		filesize <200KB and (1 of ($x*) or 2 of them )
}
