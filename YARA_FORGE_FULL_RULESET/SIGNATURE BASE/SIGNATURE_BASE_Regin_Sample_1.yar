rule SIGNATURE_BASE_Regin_Sample_1 : FILE
{
	meta:
		description = "Semiautomatically generated YARA rule - file-3665415_sys"
		author = "Florian Roth"
		id = "13478652-155f-52ba-af16-53f27c92e052"
		date = "2014-11-25"
		modified = "2023-12-15"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_regin_fiveeyes.yar#L145-L173"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"
		logic_hash = "e8291b4a68924dccdd825ee2cc8930acb794e92e0302598872ec78eb0bf8504f"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "Getting PortName/Identifier failed - %x" fullword ascii
		$s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
		$s2 = "External Naming Failed - Status %x" fullword ascii
		$s3 = "------- Same multiport - different interrupts" fullword ascii
		$s4 = "%x occurred prior to the wait - starting the" fullword ascii
		$s5 = "'user registry info - userPortIndex: %d" fullword ascii
		$s6 = "Could not report legacy device - %x" fullword ascii
		$s7 = "entering SerialGetPortInfo" fullword ascii
		$s8 = "'user registry info - userPort: %x" fullword ascii
		$s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
		$s10 = "Kernel debugger is using port at address %X" fullword ascii
		$s12 = "Release - freeing multi context" fullword ascii
		$s13 = "Serial driver will not load port" fullword ascii
		$s14 = "'user registry info - userAddressSpace: %d" fullword ascii
		$s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
		$s20 = "'user registry info - userIndexed: %d" fullword ascii
		$fp1 = "Enter SerialBuildResourceList" ascii fullword

	condition:
		all of them and filesize <110KB and filesize >80KB and not $fp1
}
