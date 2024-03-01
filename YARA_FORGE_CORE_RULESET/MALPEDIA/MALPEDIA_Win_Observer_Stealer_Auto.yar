rule MALPEDIA_Win_Observer_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "536559c4-9574-5591-915f-4694149d7210"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.observer_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.observer_stealer_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "7a05fc963c0665c59a8fed1a8fc722896fb246e3248a23ceef5fd4c8486da3c7"
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
		$sequence_0 = { c1ea03 0fb60c02 8bc6 83e007 0fabc1 8b442414 }
		$sequence_1 = { 8b5c2418 f6c301 746c 8b3e 85ff 7466 8b5e04 }
		$sequence_2 = { 50 ff15???????? 8b4c2460 8d442440 50 e8???????? 8d4c2440 }
		$sequence_3 = { e8???????? 68???????? 8d8d54ffffff e8???????? 68???????? 8d8d6cffffff }
		$sequence_4 = { 59 eb3b 55 8b6b04 2bee c1fd02 56 }
		$sequence_5 = { 85f6 740b 83feff 0f859a000000 eb6c 8b1c8d287e4300 }
		$sequence_6 = { 8d8d60ffffff e8???????? 59 83781408 7202 8b00 }
		$sequence_7 = { 8b442420 8918 5f 5e 5d 5b 83c40c }
		$sequence_8 = { 85d2 7912 f7da e8???????? 6a2d 8d48fe 58 }
		$sequence_9 = { 8d7c2468 894c2464 885c2450 ab ab ab ab }

	condition:
		7 of them and filesize <614400
}
