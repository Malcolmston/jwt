import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { NodeVsGo } from '../../../src/components/NodeVsGo';
import { JWT } from '../../../src/data';

describe('NodeVsGo', () => {
  it('renders the comparison heading and both Node and Go columns', () => {
    const { container } = render(<NodeVsGo lib={JWT} />);
    expect(container.querySelector(`#${JWT.id}-cmp`)).not.toBeNull();
    expect(screen.getByText('Node')).toBeInTheDocument();
    expect(screen.getByText('Go')).toBeInTheDocument();
    expect(container.querySelectorAll('.compare .code').length).toBe(2);
  });
});
