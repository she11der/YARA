rule MALPEDIA_Win_Headertip_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "85fa344d-9a7e-5c14-be69-b6cdc5f3bcac"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.headertip"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.headertip_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "4007b2c1a7322a986be26c8429a660608ab1b4d0812b16868306a2db8cbc4c12"
		score = 75
		quality = 75
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
		$sequence_0 = { 85c0 7434 8b07 ff4d08 03c3 56 }
		$sequence_1 = { 57 ff15???????? 59 eb32 ffd6 }
		$sequence_2 = { c645d274 c645d36f c645d472 c645d579 c645d657 885dd7 c645ac47 }
		$sequence_3 = { c6458d75 c6458e65 c6458f72 c6459079 c645914f c6459270 c6459374 }
		$sequence_4 = { 56 8d45ec 50 8d45f0 50 6813000020 }
		$sequence_5 = { 894df4 8955fc f7c60000ffff 7513 81e6ffff0000 2b7010 }
		$sequence_6 = { 03c6 ebea 56 8b742410 57 }
		$sequence_7 = { 58 668945f8 6a32 58 668945fa 33c0 668945fc }
		$sequence_8 = { ff15???????? a3???????? 3bc6 0f84c0000000 53 8d4df4 }
		$sequence_9 = { 50 ff15???????? 83c414 56 b80013e084 50 56 }

	condition:
		7 of them and filesize <174080
}