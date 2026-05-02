import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  retryKey: number;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    retryKey: 0,
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  private handleRetry = () => {
    // Incrementing retryKey forces React to unmount and remount the child
    // tree, clearing any broken state that caused the original error.
    this.setState(prev => ({ hasError: false, error: null, retryKey: prev.retryKey + 1 }));
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <h2>Algo salió mal en este componente</h2>
          <pre>{this.state.error?.message}</pre>
          <button onClick={this.handleRetry}>
            Reintentar
          </button>
        </div>
      );
    }

    // The key prop forces a full remount of children when retryKey changes.
    return (
      <div key={this.state.retryKey} style={{ display: 'contents' }}>
        {this.props.children}
      </div>
    );
  }
}
