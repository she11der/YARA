import "pe"

rule SIGNATURE_BASE_Ammyy_Admin_AA_V3
{
	meta:
		description = "Remote Admin Tool used by APT group Anunak (ru) - file AA_v3.4.exe and AA_v3.5.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bb140cb7-9f56-5acb-883e-080dfd3f60d5"
		date = "2014-12-22"
		modified = "2023-12-05"
		reference = "http://goo.gl/gkAg2E"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2794-L2818"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6ab1de9f3b58cdb2c03f2d72986772333f8b81c98e6cbfd941f20b2fed1c5ff2"
		score = 55
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b130611c92788337c4f6bb9e9454ff06eb409166"
		hash2 = "07539abb2623fe24b9a05e240f675fa2d15268cb"

	strings:
		$x1 = "S:\\Ammyy\\sources\\target\\TrService.cpp" fullword ascii
		$x2 = "S:\\Ammyy\\sources\\target\\TrDesktopCopyRect.cpp" fullword ascii
		$x3 = "Global\\Ammyy.Target.IncomePort" fullword ascii
		$x4 = "S:\\Ammyy\\sources\\target\\TrFmFileSys.cpp" fullword ascii
		$x5 = "Please enter password for accessing remote computer" fullword ascii
		$s1 = "CreateProcess1()#3 %d error=%d" fullword ascii
		$s2 = "CHttpClient::SendRequest2(%s, %s, %d) error: invalid host name." fullword ascii
		$s3 = "ERROR: CreateProcessAsUser() error=%d, session=%d" fullword ascii
		$s4 = "ERROR: FindProcessByName('explorer.exe')" fullword ascii

	condition:
		2 of ($x*) or all of ($s*)
}
