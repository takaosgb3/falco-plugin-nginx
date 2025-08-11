import type { NextConfig } from "next";
import { withContentlayer } from 'next-contentlayer2'

const nextConfig: NextConfig = {
  images: {
    domains: ['localhost'],
  },
};

export default withContentlayer(nextConfig);
