rule BINARYALERT_Hacktool_Multi_Jtesta_Ssh_Mitm
{
	meta:
		description = "intercepts ssh connections to capture credentials"
		author = "@fusionrace"
		id = "fa8362e2-83d3-5830-8952-502684ad66f9"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/jtesta/ssh-mitm"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/multi/hacktool_multi_jtesta_ssh_mitm.yara#L1-L12"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "1d19c83f7d648a0d30074debcd76ff0faf72afa6722251661f8640abdc12a2a9"
		score = 50
		quality = 80
		tags = ""

	strings:
		$a1 = "INTERCEPTED PASSWORD:" wide ascii
		$a2 = "more sshbuf problems." wide ascii

	condition:
		all of ($a*)
}
