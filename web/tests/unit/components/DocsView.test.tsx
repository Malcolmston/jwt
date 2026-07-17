import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DocsView } from '../../../src/components/DocsView';
import type { DocIndex } from 'go-ui';

// A minimal DocIndex the stubbed fetch returns for DocsApp's doc.json request.
const DOC_INDEX: DocIndex = {
  module: 'github.com/malcolmston/jwt',
  packages: [
    {
      importPath: 'github.com/malcolmston/jwt',
      name: 'jwt',
      synopsis: 'Package jwt is a standard-library-only implementation of JSON Web Tokens (RFC 7519).',
      doc: 'Package jwt is a standard-library-only implementation of JSON Web Tokens (RFC 7519).',
      consts: [],
      vars: [],
      types: [
        {
          name: 'Token',
          signature: 'type Token struct{}',
          doc: 'Token represents a JWT.',
          consts: [],
          vars: [],
          funcs: [],
          methods: [],
        },
      ],
      funcs: [{ name: 'Sign', signature: 'func Sign(claims Claims, method SigningMethod, key any) (string, error)', doc: 'Sign builds and signs a token.' }],
    },
  ],
};

describe('DocsView', () => {
  beforeEach(() => {
    // DocsApp fetches doc.json; return the small index.
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      if (String(input).includes('doc.json')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(DOC_INDEX) } as Response);
      }
      return new Promise<Response>(() => {});
    }) as unknown as typeof fetch;
  });

  it('renders the inline React API reference from the fetched doc.json', async () => {
    const { container } = render(<DocsView />);
    expect(container.querySelector('#view-docs')).not.toBeNull();
    expect(
      screen.getByRole('heading', { level: 2, name: /API documentation/ }),
    ).toBeInTheDocument();

    // DocsApp fetches asynchronously, then renders the package view + symbols.
    expect(await screen.findByRole('heading', { name: /package jwt/ })).toBeInTheDocument();
    expect(container.querySelector('#sym-Sign'), 'func Sign symbol card').not.toBeNull();
    expect(container.querySelector('#sym-Token'), 'type Token symbol card').not.toBeNull();

    // The secondary link to the raw generated static HTML remains.
    expect(screen.getByRole('link', { name: /Open the raw generated HTML/ })).toHaveAttribute('href', './api/');
  });
});
