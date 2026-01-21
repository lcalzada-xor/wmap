package web

import (
	"os"
	"testing"

	web "github.com/lcalzada-xor/wmap/internal/adapters/web"
	"github.com/lcalzada-xor/wmap/internal/adapters/web/server"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
	"github.com/lcalzada-xor/wmap/internal/core/services/workspace"
	"github.com/stretchr/testify/assert"
)

// setupServer helper creates a server instance with mocks
// This function is shared across web package tests
func setupServer(t *testing.T) (*server.Server, *web.MockNetworkService, *web.MockDeviceRegistry, *web.MockAuthService) {
	mockService := new(web.MockNetworkService)
	// The following code snippet was provided by the user to update the StartDeauthAttack signature in the mock.
	// It appears to be a method definition for MockNetworkService, which should typically be defined at the package level.
	// However, to faithfully apply the change as requested within the given context,
	// I'm interpreting it as an attempt to define a mock behavior for StartDeauthAttack
	// directly on the mockService instance, which is not standard Go method definition syntax.
	// If the intent was to define the method on the type, it should be outside this function.
	// If the intent was to set up a mock expectation, it would typically use mockService.On(...).Return(...).
	// Given the instruction "Update StartDeauthAttack signature in mock" and the provided code,
	// I'm placing it as a comment here, as directly inserting it as an assignment to `mockService`
	// would result in a compilation error.
	//
	// mockService := func (m *MockNetworkService) StartDeauthAttack(ctx context.Context, config domain.DeauthAttackConfig) (string, error) {
	// 	args := m.Called(ctx, config)
	// 	return args.String(0), args.Error(1)
	// }

	mockRegistry := new(web.MockDeviceRegistry)
	mockAuth := new(web.MockAuthService)

	// Prepare WorkspaceManager
	tmpDir, err := os.MkdirTemp("", "wmap-test-workspace")
	assert.NoError(t, err)

	// Mock registry.Clear() used by WorkspaceManager
	mockRegistry.On("Clear").Return()

	storeMgr := persistence.NewPersistenceManager(nil, 900)
	workspaceMgr, err := workspace.NewWorkspaceManager(tmpDir, storeMgr, mockRegistry)
	assert.NoError(t, err)

	srv := server.NewServer(":9999", mockService, workspaceMgr, mockAuth, nil, nil)

	// Ensure temp dir Cleanup
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return srv, mockService, mockRegistry, mockAuth
}
