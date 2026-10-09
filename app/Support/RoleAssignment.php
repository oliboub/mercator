<?php

namespace App\Support;

use App\Models\Role;
use App\Models\User;
use Symfony\Component\HttpFoundation\Response;

/**
 * Garde-fou contre l'élévation de privilèges par la gestion des utilisateurs
 * (GHSA-4x92-9hqx-5f58) : détenir user_create / user_edit ne permet pas de distribuer
 * plus de droits que l'on n'en a soi-même.
 *
 * Pour un non-administrateur :
 *  - un rôle n'est attribuable (ou retirable) que si toutes ses permissions sont détenues par
 *    l'acteur dans le périmètre de ce rôle — le rôle Admin ne l'est donc jamais ;
 *  - un utilisateur n'est gérable (modification, suppression) que si tous ses rôles sont
 *    attribuables par l'acteur — un administrateur ou un utilisateur plus privilégié ne l'est
 *    donc jamais (pas de changement de mot de passe ou d'e-mail menant à une prise de compte).
 */
class RoleAssignment
{
    public const ADMIN_ROLE_ID = 1;

    /**
     * @return list<int>|null identifiants des rôles attribuables par l'acteur (null = tous)
     */
    public static function grantableRoleIds(User $actor): ?array
    {
        if ($actor->isAdmin()) {
            return null;
        }

        $byPerimeter = $actor->permissionsByPerimeter();
        $flat = array_values(array_unique(array_merge([], ...array_values($byPerimeter))));
        $perimeterScoped = PerimeterSettings::isEnabled();

        return Role::query()
            ->with('permissions')
            ->whereKeyNot(self::ADMIN_ROLE_ID)
            ->get()
            ->filter(function (Role $role) use ($byPerimeter, $flat, $perimeterScoped) {
                $held = $perimeterScoped ? ($byPerimeter[(int) $role->perimeter_id] ?? []) : $flat;

                return array_diff($role->permissions->pluck('title')->all(), $held) === [];
            })
            ->pluck('id')
            ->map(fn ($id) => (int) $id)
            ->values()
            ->all();
    }

    /**
     * L'acteur peut-il modifier ou supprimer cet utilisateur ?
     */
    public static function canManageUser(User $actor, User $target): bool
    {
        $grantable = self::grantableRoleIds($actor);
        if ($grantable === null) {
            return true;
        }

        return array_diff(self::currentRoleIds($target), $grantable) === [];
    }

    /**
     * Interrompt la requête (403) si l'acteur ne peut pas gérer l'utilisateur cible.
     */
    public static function authorizeManage(User $actor, User $target): void
    {
        abort_unless(self::canManageUser($actor, $target), Response::HTTP_FORBIDDEN, '403 Forbidden');
    }

    /**
     * Interrompt la requête (403) si le passage des rôles actuels de la cible (aucun pour une
     * création) aux rôles demandés ajoute ou retire un rôle non attribuable par l'acteur.
     *
     * @param  array<int, mixed>  $requestedRoleIds
     */
    public static function authorizeRoles(User $actor, ?User $target, array $requestedRoleIds): void
    {
        $grantable = self::grantableRoleIds($actor);
        if ($grantable === null) {
            return;
        }

        $current = $target ? self::currentRoleIds($target) : [];
        $requested = array_values(array_unique(array_map('intval', $requestedRoleIds)));

        $changed = array_merge(array_diff($requested, $current), array_diff($current, $requested));

        abort_unless(array_diff($changed, $grantable) === [], Response::HTTP_FORBIDDEN, '403 Forbidden');
    }

    /**
     * @return list<int>
     */
    private static function currentRoleIds(User $user): array
    {
        return $user->roles()->pluck('roles.id')->map(fn ($id) => (int) $id)->all();
    }
}
