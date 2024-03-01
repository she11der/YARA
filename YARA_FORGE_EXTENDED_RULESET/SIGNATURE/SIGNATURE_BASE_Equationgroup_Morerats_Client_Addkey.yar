rule SIGNATURE_BASE_Equationgroup_Morerats_Client_Addkey : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "a025e379-c24e-56ac-b53c-bd38d51f3437"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1102-L1117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ec5b7499e3c3cc6b581c381ae61a4c987691c0d93dd589a5907fd7419335963a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6c67c03716d06a99f20c1044585d6bde7df43fee89f38915db0b03a42a3a9f4b"

	strings:
		$x1 = "print '  -s storebin  use storebin as the Store executable\\n'" fullword ascii
		$x2 = "os.system('%s --file=\"%s\" --wipe > /dev/null' % (storebin, b))" fullword ascii
		$x3 = "print '  -k keyfile   the key text file to inject'" fullword ascii

	condition:
		( filesize <20KB and 1 of them )
}
