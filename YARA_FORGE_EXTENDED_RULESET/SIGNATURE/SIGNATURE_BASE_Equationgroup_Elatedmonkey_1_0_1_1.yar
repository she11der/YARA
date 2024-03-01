rule SIGNATURE_BASE_Equationgroup_Elatedmonkey_1_0_1_1 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file elatedmonkey.1.0.1.1.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "d8915305-2ed7-50b7-84d0-b139a6d3481a"
		date = "2017-04-08"
		modified = "2022-08-18"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L816-L832"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "756337ecb951357c5440ea2fe010982089539c35dc556288d61db6de22348c1f"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "bf7a9dce326604f0681ca9f7f1c24524543b5be8b6fcc1ba427b18e2a4ff9090"

	strings:
		$s1 = "Usage: $0 ( -s IP PORT | CMD )" fullword ascii
		$s2 = "os.execl(\"/bin/sh\", \"/bin/sh\", \"-c\", \"$CMD\")" fullword ascii
		$s3 = "PHP_SCRIPT=\"$HOME/public_html/info$X.php\"" fullword ascii
		$s4 = "cat > /dev/tcp/127.0.0.1/80 <<" ascii

	condition:
		filesize <15KB and 2 of them
}
