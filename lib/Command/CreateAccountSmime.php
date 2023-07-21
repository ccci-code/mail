<?php

declare(strict_types=1);

/**
 * @author Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * Mail
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\Mail\Command;

use OCA\Mail\Db\MailAccount;
use OCA\Mail\Db\SmimeCertificate;
use OCA\Mail\Db\SmimeCertificateMapper;
use OCA\Mail\Service\AccountService;
use OCP\IUserManager;
use OCP\Security\ICrypto;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;


class CreateAccountSmime extends Command
{
	public const ARGUMENT_USER_ID = 'user-id';
	public const ARGUMENT_NAME = 'name';
	public const ARGUMENT_EMAIL = 'email';
	public const ARGUMENT_AUTH_METHOD = 'auth-method';
	public const ARGUMENT_IMAP_HOST = 'imap-host';
	public const ARGUMENT_IMAP_PORT = 'imap-port';
	public const ARGUMENT_IMAP_SSL_MODE = 'imap-ssl-mode';
	public const ARGUMENT_IMAP_USER = 'imap-user';
	public const ARGUMENT_IMAP_PASSWORD = 'imap-password';
	public const ARGUMENT_SMTP_HOST = 'smtp-host';
	public const ARGUMENT_SMTP_PORT = 'smtp-port';
	public const ARGUMENT_SMTP_SSL_MODE = 'smtp-ssl-mode';
	public const ARGUMENT_SMTP_USER = 'smtp-user';
	public const ARGUMENT_SMTP_PASSWORD = 'smtp-password';

	public const ARGUMENT_SMIME_CERTIFICATE = 'smime-certificate';
	public const ARGUMENT_SMIME_PRIVATEKEY = 'smime-privatekey';

	private AccountService $accountService;
	private ICrypto $crypto;
	private IUserManager $userManager;
	private SmimeCertificateMapper $certificateMapper;

	public function __construct(
		AccountService $service,
		ICrypto $crypto,
		IUserManager $userManager,
		SmimeCertificateMapper $certificateMapper
	) {
		parent::__construct();

		$this->accountService = $service;
		$this->crypto = $crypto;
		$this->userManager = $userManager;
		$this->certificateMapper = $certificateMapper;
	}

	/**
	 * @return void
	 */
	protected function configure()
	{
		$this->setName('mail:account:smime');
		$this->setDescription('creates IMAP account');
		$this->addArgument(self::ARGUMENT_USER_ID, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_NAME, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_EMAIL, InputArgument::REQUIRED);

		$this->addArgument(self::ARGUMENT_IMAP_HOST, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_IMAP_PORT, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_IMAP_SSL_MODE, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_IMAP_USER, InputArgument::REQUIRED);

		$this->addArgument(self::ARGUMENT_SMTP_HOST, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_SMTP_PORT, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_SMTP_SSL_MODE, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_SMTP_USER, InputArgument::REQUIRED);

		$this->addArgument(self::ARGUMENT_SMIME_CERTIFICATE, InputArgument::REQUIRED);
		$this->addArgument(self::ARGUMENT_SMIME_PRIVATEKEY, InputArgument::REQUIRED);

		$this->addArgument(self::ARGUMENT_AUTH_METHOD, InputArgument::OPTIONAL, 'password or xoauth2', 'password');


	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$userId = $input->getArgument(self::ARGUMENT_USER_ID);
		$name = $input->getArgument(self::ARGUMENT_NAME);
		$email = $input->getArgument(self::ARGUMENT_EMAIL);
		$authMethod = $input->getArgument(self::ARGUMENT_AUTH_METHOD);

		$imapHost = $input->getArgument(self::ARGUMENT_IMAP_HOST);
		$imapPort = $input->getArgument(self::ARGUMENT_IMAP_PORT);
		$imapSslMode = $input->getArgument(self::ARGUMENT_IMAP_SSL_MODE);
		$imapUser = $input->getArgument(self::ARGUMENT_IMAP_USER);

		$smtpHost = $input->getArgument(self::ARGUMENT_SMTP_HOST);
		$smtpPort = $input->getArgument(self::ARGUMENT_SMTP_PORT);
		$smtpSslMode = $input->getArgument(self::ARGUMENT_SMTP_SSL_MODE);
		$smtpUser = $input->getArgument(self::ARGUMENT_SMTP_USER);

		$smimeCertificate = $input->getArgument(self::ARGUMENT_SMIME_CERTIFICATE);
		$smimePrivatekey = $input->getArgument(self::ARGUMENT_SMIME_PRIVATEKEY);

		if (!$this->userManager->userExists($userId)) {
			$output->writeln("<error>User $userId does not exist</error>");
			return 1;
		}

		if (!file_exists($smimeCertificate)) {
			echo "Public certificate $smimeCertificate doesn't exist\n";
			die();
		}

		if (!file_exists($smimePrivatekey)) {
			echo "Private key $smimePrivatekey doesn't exist\n";
			die();
		}
		$rawCert = file_get_contents($smimeCertificate);
		$rawKey = file_get_contents($smimePrivatekey);

		if (!openssl_x509_check_private_key($rawCert, $rawKey)) {
			echo "Private key does not match certificate or is protected by a passphrase\n";
			die();
		}

		$cert = $this->crypto->encrypt($rawCert);
		$pkey = $this->crypto->encrypt($rawKey);


		$certificate = new SmimeCertificate();
		$certificate->setUserId($userId);
		$certificate->setEmailAddress($email);
		$certificate->setCertificate($cert);
		$certificate->setPrivateKey($pkey);
		$newCert = $this->certificateMapper->insert($certificate);
		echo "Debug: New certificate ID: " . $newCert->id . "\n";


		$account = new MailAccount();
		$account->setUserId($userId);
		$account->setName($name);
		$account->setEmail($email);
		$account->setAuthMethod($authMethod);

		$account->setInboundHost($imapHost);
		$account->setInboundPort((int) $imapPort);
		$account->setInboundSslMode($imapSslMode);
		$account->setInboundUser($imapUser);
		$account->setInboundPassword(null);

		$account->setOutboundHost($smtpHost);
		$account->setOutboundPort((int) $smtpPort);
		$account->setOutboundSslMode($smtpSslMode);
		$account->setOutboundUser($smtpUser);
		$account->setOutboundPassword(null);
		$account->setSmimeCertificateId($newCert->id);
		$account->setEditorMode("richtext");

		$account = $this->accountService->save($account);

		$output->writeln("<info>Account " . $account->getId() . " for $email created</info>");

		return 0;
	}
}
