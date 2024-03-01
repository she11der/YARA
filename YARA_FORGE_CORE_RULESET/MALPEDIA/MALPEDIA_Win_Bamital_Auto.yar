rule MALPEDIA_Win_Bamital_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3baca492-b609-5d4f-80bb-c68e186e995b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bamital"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bamital_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "80aaa696b23b77db92b802971fab9d7fd90e414992e8440ec6c57f40448ba374"
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
		$sequence_0 = { eb05 83c001 ebe0 52 ff75fc e8???????? }
		$sequence_1 = { 8ac4 8807 83c701 e2d8 c9 c20800 55 }
		$sequence_2 = { ff75dc ff75d4 57 e8???????? 8b55fc 8945fc 0bd2 }
		$sequence_3 = { e8???????? 8b55fc 8945fc 0bd2 }
		$sequence_4 = { 0bc0 741f 50 83c001 50 }
		$sequence_5 = { b800000000 c9 c20400 55 8bec 83c4f0 }
		$sequence_6 = { 56 57 53 8b5d0c 8b7508 }
		$sequence_7 = { ff7508 ff75f4 e8???????? 68e8070000 }
		$sequence_8 = { 6a28 e8???????? 8945fc ff7508 e8???????? 8945f8 e8???????? }
		$sequence_9 = { 8a07 3c39 7208 3c7e 7704 2c19 eb13 }

	condition:
		7 of them and filesize <90112
}