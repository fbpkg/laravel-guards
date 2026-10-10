<?php

namespace Fbpkg\Guards\Middleware;

use Closure;
use Fbpkg\Guards\Guards\GuardManager;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Restricts routes to unauthenticated visitors.
 */
class GuestOnly
{
    /**
     * Create a new guest middleware.
     *
     * @param GuardManager $guards The authentication guard manager.
     */
    public function __construct(
        protected GuardManager $guards,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param Request $request The incoming request.
     * @param Closure $next The next middleware.
     * @param string $guard The guard name.
     * @param string $behavior The authenticated behavior.
     *
     * @return Response The response.
     */
    public function handle(
        Request $request,
        Closure $next,
        string $guard = 'web',
        string $behavior = 'redirect',
    ): Response {
        if (!$this->guards->guard($guard)->check()) {
            return $next($request);
        }

        if ($behavior === 'abort') {
            abort(Response::HTTP_FORBIDDEN);
        }

        if ($behavior !== 'redirect') {
            throw new InvalidArgumentException(
                "Unsupported guest middleware behavior [{$behavior}].",
            );
        }

        return redirect($this->guards->guard($guard)->authenticatedRedirect());
    }
}
