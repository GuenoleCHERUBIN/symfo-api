<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\SubscriptionRepository;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use FOS\RestBundle\Controller\AbstractFOSRestController;
use FOS\RestBundle\Controller\Annotations as Rest;


class UserController extends AbstractFOSRestController
{

    private $userRepository;
    private $subscriptionRepository;
    private $em

    public function __construct(UserRepository $userRepository, SubscriptionRepository $subscriptionRepository, EntityManagerInterface $em )
    {
        $this->userRepository = $userRepository;
        $this->subscriptionRepository = $subscriptionRepository;
        $this->em = $em;
    }

    /**
     * @Rest\Get("/api/users/{email}")
     *
     */
    public function getApiUser(User $user)
    {
        return $this->view($user);
    }

    /**
     * @Rest\Get("/api/users")
     *
     */
    public function getApiUsers()
    {
        $users = $this->userRepository->findAll();
        return $this->view($users);
    }
    /**
     * @rest\Get("/api/admin/users")
     */
    public function getApiUsersAdmin()
    {
        $users = $this->userRepository->findAll();
        return $this->view($users);
    }
    /**
     * @Rest\GET("/api/admin/subsciption")
     */
    public function getApiSubscriptionAdmin()
    {
        $subscription = $this->subscriptionRepository->findAll();
        return $this->view($subscription);
    }

    /**
     * @Rest\Post("/api/users")
     *
     */
    public function postApiUser(User $user)
    {
    }

    /**
     * @Rest\Patch("/api/users/{email}")
     *
     */
    public function patchApiUSer(User $user)
    {
    }

    /**
     * @Rest\Delete("/api/users/{email}")
     *
     */
    public function deleteApiUser(USer $user)
    {
        $this->em->remove($user);
        $this->em->flush();
        

    }

}
