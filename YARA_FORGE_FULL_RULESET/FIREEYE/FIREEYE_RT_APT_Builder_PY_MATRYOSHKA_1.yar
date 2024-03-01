rule FIREEYE_RT_APT_Builder_PY_MATRYOSHKA_1
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "0135f3bb-28b3-5fc4-85a2-b12c46c8bc45"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/MATRYOSHKA/production/yara/APT_Builder_PY_MATRYOSHKA_1.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "25a97f6dba87ef9906a62c1a305ee1dd"
		logic_hash = "71b26f4b319429ac356b55d22bccd1da85894d61f8c96452422de78d2d893420"
		score = 75
		quality = 25
		tags = ""
		rev = 1

	strings:
		$s1 = ".pop(0)])"
		$s2 = "[1].replace('unsigned char buf[] = \"'"
		$s3 = "binascii.hexlify(f.read()).decode("
		$s4 = "os.system(\"cargo build {0} --bin {1}\".format("
		$s5 = "shutil.which('rustc')"
		$s6 = "~/.cargo/bin"
		$s7 = /[\x22\x27]\\\\x[\x22\x27]\.join\(\[\w{1,64}\[\w{1,64}:\w{1,64}[\x09\x20]{0,32}\+[\x09\x20]{0,32}2\]/

	condition:
		all of them
}
