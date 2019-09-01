<?php


namespace App\Authenticator;


use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class TokenAuthenticator extends AbstractGuardAuthenticator
{
    private $em;
    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }
    /**
     * Called on every request to decide if this authenticator should be*
     * used for the request. Returning false will cause this authenticator*
     * to be skipped.
     */
    public function supports(Request $request)
    {
        return $request->headers->has('X-AUTH-TOKEN');
    }
    /**
     * Called on every request. Return whatever credentials you want to*
     * be passed to getUser() as $credentials.
     */
    public function getCredentials(Request $request)
    {
        return ['token' => $request->headers->get('X-AUTH-TOKEN'),];
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $apiKey = $credentials['token'];

        if (null === $apiKey)
        {
            return;
        }

        return $this->em->getRepository(User::class)
            ->findOneBy(['apiKey'=>$apiKey]);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return null;
    }
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())
        // or to translate this message
        // $this->translator->trans($exception->getMessageKey(), $exception->getMessageData())];return new JsonResponse($data, Response::HTTP_FORBIDDEN);
        ];

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = [
            // you might translate this message
            'message' => 'Authentication Required'
        ];
        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }
    public function supportsRememberMe()
    {
        return false;
    }
}