rule SIGNATURE_BASE_Equationgroup_Envisioncollision : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file envisioncollision"
		author = "Florian Roth (Nextron Systems)"
		id = "8d512d9a-45a5-514a-bee1-a364beeaf560"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L485-L501"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8cd8c24b212ca71feb6093682fc614c88790c10d7c7d72dac65b047e5791894a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "75d5ec573afaf8064f5d516ae61fd105012cbeaaaa09c8c193c7b4f9c0646ea1"

	strings:
		$x1 = "mysql \\$D --host=\\$H --user=\\$U --password=\\\"\\$P\\\" -e \\\"select * from \\$T" fullword ascii
		$x2 = "Window 3: $0 -Uadmin -Ppassword -i127.0.0.1 -Dipboard -c\\\"sleep 500|nc" fullword ascii
		$s3 = "$ua->agent(\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\");" fullword ascii
		$s4 = "$url = $host . \"/admin/index.php?adsess=\" . $enter . \"&app=core&module=applications&section=hooks&do=install_hook\";" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <20KB and 1 of ($x*)) or (2 of them )
}
