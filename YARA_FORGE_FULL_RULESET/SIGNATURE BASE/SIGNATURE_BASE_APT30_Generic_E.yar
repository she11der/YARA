rule SIGNATURE_BASE_APT30_Generic_E : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "69e76a59-3529-541d-9017-07e6d67fbda4"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L165-L183"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5ccf1f1334dc300d13aa8dbc080d2d839815d102958fde2b8709c11f522412fd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1dbb584e19499e26398fb0a7aa2a01b7"
		hash2 = "572c9cd4388699347c0b2edb7c6f5e25"
		hash3 = "8ff473bedbcc77df2c49a91167b1abeb"
		hash4 = "a813eba27b2166620bd75029cc1f04b0"
		hash5 = "b5546842e08950bc17a438d785b5a019"

	strings:
		$s0 = "Nkfvtyvn}" ascii
		$s6 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
