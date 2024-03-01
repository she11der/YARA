rule MALPEDIA_Win_Redalpha_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "18d7b39f-1fe8-5b57-91e8-72bb40b0300f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redalpha"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.redalpha_auto.yar#L1-L286"
		license_url = "N/A"
		logic_hash = "062f534aa7bc989cb92a0f507bdc74bdcfcc089d3142c94dc9dd9b9510e4dbdc"
		score = 75
		quality = 73
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { e8???????? 83c40c c0e304 0fb6c3 50 }
		$sequence_1 = { 8b3e 8bce e8???????? 8b4df8 }
		$sequence_2 = { 4585c0 7417 0f1f4000 410fb602 4d8d5201 03c8 }
		$sequence_3 = { 443bd3 7d0b 6645019489a40a0000 eb33 }
		$sequence_4 = { 8b4004 c74408e840d24300 8b41e8 8b5004 }
		$sequence_5 = { 8b3d???????? eb96 8b8b48010000 e8???????? 8bce e8???????? 8b7e04 }
		$sequence_6 = { 8b3f ff750c 53 6aff }
		$sequence_7 = { 8b3e 897df4 0fb607 0fb64f01 }
		$sequence_8 = { 42803c0000 75f6 49ffc0 488d4f0d 488d542450 }
		$sequence_9 = { e8???????? 488d043b 4d63c4 488d8dea020000 }
		$sequence_10 = { 498d4505 894208 d3e5 ffcd 23dd }
		$sequence_11 = { 488b4b10 488b5010 410fb60411 41880408 ff4328 ff4338 }
		$sequence_12 = { 448d4858 e8???????? 85c0 7556 }
		$sequence_13 = { 8b3e 8bcb d3e8 83e001 895d08 }
		$sequence_14 = { 488d542458 4803d0 488bcb e8???????? }
		$sequence_15 = { 8b3d???????? ffd7 ffb548f7ffff ffd7 }
		$sequence_16 = { 50 e8???????? 83c418 c785f0fdffff00000000 8d85f0fdffff 50 6a0b }
		$sequence_17 = { 0f8413050000 8b3c8d8c864000 85ff 755d 33c0 89859cf6ffff 89855cfcffff }
		$sequence_18 = { c3 55 8bec 81ec04010000 56 68cf010040 6a00 }
		$sequence_19 = { 8d7608 660fd60f 8d7f08 8b048d74e84000 }
		$sequence_20 = { 50 8d45f4 64a300000000 683f000f00 }
		$sequence_21 = { 897c2428 e8???????? 83c410 8d442424 50 }
		$sequence_22 = { 50 e8???????? 6aff c645fc01 ff75dc }
		$sequence_23 = { 8b5df4 8bf7 8b4b04 85c9 0f85f2000000 33c0 }
		$sequence_24 = { 7605 e8???????? 8b4f14 8bf0 }
		$sequence_25 = { e8???????? 83f801 7512 68d0070000 ff15???????? e8???????? eb39 }
		$sequence_26 = { 7512 8b04bd30744100 807c302900 7504 }
		$sequence_27 = { 8b8fbc000000 52 ff7730 8b01 ff5004 ff75ec }
		$sequence_28 = { c1f806 83e13f 6bc930 53 56 8b048530744100 33db }
		$sequence_29 = { 89b8bc000000 ff15???????? 894708 ff7518 8b4514 }
		$sequence_30 = { 6bc830 894de0 8b049d581f4000 0fb6440828 83e001 7469 }

	condition:
		7 of them and filesize <606208
}
