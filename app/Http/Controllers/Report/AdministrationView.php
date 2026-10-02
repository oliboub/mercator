<?php

namespace App\Http\Controllers\Report;

use App\Http\Controllers\Controller;
use App\Http\Controllers\Report\Concerns\AutoloadsRelations;
use App\Models\AdminUser;
use App\Models\Annuaire;
use App\Models\Cartographer;
use App\Models\Domain;
use App\Models\ForestAd;
use App\Models\ZoneAdmin;
use App\Services\Graph\AdministrationGraphBuilder;
use App\Services\Graph\GraphSize;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\Response;

class AdministrationView extends Controller
{
    use AutoloadsRelations;

    /**
     * Build the administration report view populated with zones, annuaires, forests, domains, and admin users.
     *
     * Aborts with HTTP 403 Forbidden if the current user is denied the 'reports_access' gate.
     *
     * @return View The rendered 'admin/reports/administration' view with keys:
     *              - 'zones' => collection of ZoneAdmin
     *              - 'annuaires' => collection of Annuaire
     *              - 'forests' => collection of ForestAd
     *              - 'domains' => collection of Domain
     *              - 'adminUsers' => collection of AdminUser
     */
    public function generate(): View
    {
        $allowed = Gate::allows('explore_access') || Cartographer::canAccessAny([ZoneAdmin::class, Annuaire::class, ForestAd::class, Domain::class]);
        abort_if(! $allowed, Response::HTTP_FORBIDDEN, '403 Forbidden');

        $zones = Cartographer::scopedQuery(ZoneAdmin::query())->get();
        $annuaires = Cartographer::scopedQuery(Annuaire::query())->with(['zoneAdmin', 'application'])->get();
        $forests = Cartographer::scopedQuery(ForestAd::query())->get();
        $domains = Cartographer::scopedQuery(Domain::query())->get();
        $adminUsers = Cartographer::scopedQuery(AdminUser::query())->get();

        $this->autoloadRelations($zones, $annuaires, $forests, $domains, $adminUsers);

        // Compte les nœuds avant de construire le DOT : un graphe trop grand n'est ni construit ni envoyé
        // (+ les applications des annuaires, ajoutées par AdministrationGraphBuilder)
        $graphTooLarge = GraphSize::tooLarge(GraphSize::count(
            $zones, $annuaires, $forests, $domains, $adminUsers,
            $annuaires->pluck('application')->filter()->unique('id')
        ));

        $graphBuilder = new AdministrationGraphBuilder;

        return view('admin/reports/administration')
            ->with('zones', $zones)
            ->with('annuaires', $annuaires)
            ->with('forests', $forests)
            ->with('domains', $domains)
            ->with('adminUsers', $adminUsers)
            ->with('graphTooLarge', $graphTooLarge)
            ->with('dotSrc', $graphTooLarge ? '' : $graphBuilder->buildDot($zones, $annuaires, $forests, $domains, $adminUsers))
            ->with('imageManifest', $graphBuilder->imageManifest());
    }
}
